# SSRF (Server-Side Request Forgery) Bug Bounty Reports

> A collection of accepted/disclosed SSRF vulnerability reports from bug bounty programs.

---

### 1. SSRF in Exchange Leads to ROOT Access (Shopify)
- **Severity:** Critical (CVSS 10.0)
- **Vulnerability Type:** SSRF to RCE
- **Platform:** HackerOne
- **Program:** Shopify
- **Bounty:** $25,000
- **Description:** A server-side request forgery bug was found in the screenshotting functionality of Shopify Exchange. The SSRF could be escalated to gain root access to any container in a particular infrastructure subset. The screenshotting service would fetch arbitrary URLs, which could be pointed at internal services.
- **How It Was Found:** Testing the screenshot generation feature by supplying internal/cloud metadata URLs. Identified that the service made server-side HTTP requests to render pages.
- **Impact:** Full root access to containers in Shopify's infrastructure, potential access to customer data and internal services.
- **Key Takeaway:** Screenshot/thumbnail generation features are classic SSRF vectors. Any feature that fetches URLs server-side should be tested for SSRF. Chain SSRF with cloud metadata access for maximum impact.
- **Source:** https://hackerone.com/reports/341876

### 2. SSRF on Project Import via remote_attachment_url (GitLab)
- **Severity:** Critical
- **Vulnerability Type:** SSRF
- **Platform:** HackerOne
- **Program:** GitLab
- **Bounty:** $10,000
- **Description:** An SSRF vulnerability was found in GitLab's project import functionality via the remote_attachment_url parameter on a Note. The import process would fetch remote attachments without properly validating the URL, allowing access to internal services.
- **How It Was Found:** Testing project import/export features with URLs pointing to internal services and cloud metadata endpoints.
- **Impact:** Access to internal GitLab infrastructure and cloud metadata, potential credential theft.
- **Key Takeaway:** Import/export features that accept URLs are prime SSRF targets. Test with internal IP addresses (127.0.0.1, 169.254.169.254), internal hostnames, and IPv6 addresses.
- **Source:** Referenced in HackerOne Top 100 Paid Reports

### 3. Blind SSRF on errors.hackerone.net via Sentry Misconfiguration
- **Severity:** Medium
- **Vulnerability Type:** Blind SSRF
- **Platform:** HackerOne
- **Program:** HackerOne
- **Bounty:** $3,500
- **Description:** A blind SSRF was found on HackerOne's error tracking service (errors.hackerone.net) due to a Sentry misconfiguration. The attacker could make the server issue requests to arbitrary internal or external endpoints.
- **How It Was Found:** Analyzing Sentry configuration and testing DSN/webhook endpoints for SSRF.
- **Impact:** Internal network scanning, potential access to cloud metadata and internal services.
- **Key Takeaway:** Third-party services (Sentry, Datadog, etc.) integrated into applications can introduce SSRF vulnerabilities through their configuration endpoints. Always check for exposed monitoring/logging endpoints.
- **Source:** Referenced in HackerOne SSRF disclosures

### 4. SSRF via DNS Rebinding (Snapchat)
- **Severity:** High
- **Vulnerability Type:** SSRF via DNS Rebinding
- **Platform:** HackerOne
- **Program:** Snapchat
- **Bounty:** $5,000+
- **Description:** Researchers exploited DNS rebinding to bypass SSRF protections and access internal web endpoints on Snapchat's infrastructure. The application validated the DNS resolution at request time but the DNS record was changed between validation and actual request.
- **How It Was Found:** Using DNS rebinding techniques with services like rbndr.us to bypass IP-based SSRF protections.
- **Impact:** Access to internal Snapchat services and potentially sensitive infrastructure data.
- **Key Takeaway:** DNS rebinding is an effective technique to bypass SSRF protections that validate hostnames/IPs. Use tools like singularity or rbndr.us for DNS rebinding attacks.
- **Source:** https://hackerone.com/reports/530974

### 5. SSRF Vulnerability in HackerOne Platform
- **Severity:** High
- **Vulnerability Type:** SSRF
- **Platform:** HackerOne
- **Program:** HackerOne
- **Bounty:** $2,500+
- **Description:** An SSRF vulnerability was found that allowed attackers to make internal requests from HackerOne's application servers. A lack of output sanitization in an error message allowed the attacker to access internal AWS services.
- **How It Was Found:** Testing error handling paths for URL fetching functionality, analyzing error messages for information leakage.
- **Impact:** Access to internal AWS services including EC2 metadata, potential credential theft.
- **Key Takeaway:** Error messages can leak information about internal infrastructure. Always check error responses when testing SSRF - even if the main request is blocked, error messages might reveal internal data.
- **Source:** https://hackerone.com/reports/2262382

### 6. SSRF in Webhooks Leads to AWS Private Keys (Omise)
- **Severity:** Critical
- **Vulnerability Type:** SSRF
- **Platform:** HackerOne
- **Program:** Omise
- **Bounty:** $4,913
- **Description:** An SSRF vulnerability in Omise's webhook functionality at app.hellosign.com allowed access to AWS metadata endpoint, leading to disclosure of AWS private keys and access tokens.
- **How It Was Found:** Testing webhook URL configuration with internal IP addresses and cloud metadata endpoints (169.254.169.254).
- **Impact:** Full AWS credential disclosure, potential infrastructure compromise.
- **Key Takeaway:** Webhook features are high-value SSRF targets because they explicitly fetch user-supplied URLs. Always test webhook URLs with cloud metadata endpoints.
- **Source:** https://hackerone.com/reports/508459

### 7. SSRF in hatchful.shopify.com
- **Severity:** High
- **Vulnerability Type:** SSRF
- **Platform:** HackerOne
- **Program:** Shopify
- **Bounty:** $1,000+
- **Description:** An SSRF vulnerability was found in Shopify's Hatchful logo maker service, allowing the server to make requests to internal network addresses.
- **How It Was Found:** Testing image/asset URL parameters in the logo generation feature.
- **Impact:** Internal network access from Shopify's infrastructure.
- **Key Takeaway:** Design tools and image generation services that accept URLs are common SSRF targets. Subsidiary services (like Hatchful for Shopify) may have weaker SSRF protections.
- **Source:** https://hackerone.com/reports/409701

### 8. SSRF Vulnerability in CVE-2024-42005 (Django - Internet Bug Bounty)
- **Severity:** High
- **Vulnerability Type:** SSRF
- **Platform:** HackerOne
- **Program:** Internet Bug Bounty
- **Bounty:** $2,500+
- **Description:** A vulnerability in Django's QuerySet.values() and values_list() methods could potentially be exploited for server-side request forgery under certain conditions.
- **How It Was Found:** Source code review of Django's ORM query building logic.
- **Impact:** Applications using affected Django versions could be vulnerable to SSRF through crafted query parameters.
- **Key Takeaway:** Framework-level vulnerabilities have widespread impact. Reviewing popular framework source code for SSRF vectors can lead to high-impact reports through Internet Bug Bounty.
- **Source:** https://hackerone.com/reports/2646493

### 9. Blind SSRF in Integrations via Adding Social Media Buttons (HackerOne)
- **Severity:** Medium
- **Vulnerability Type:** Blind SSRF
- **Platform:** HackerOne
- **Program:** HackerOne
- **Bounty:** $500+
- **Description:** A blind SSRF was found in HackerOne's integrations feature when adding social media buttons. The server would make requests to user-supplied URLs without proper validation.
- **How It Was Found:** Testing integration configuration endpoints with Burp Collaborator/interactsh to detect out-of-band requests.
- **Impact:** Internal network scanning capability, potential cloud metadata access.
- **Key Takeaway:** Use out-of-band detection tools (Burp Collaborator, interactsh) to detect blind SSRF where no response data is returned to the user.
- **Source:** https://hackerone.com/reports/287245

### 10. SSRF to Access AWS Metadata (Lichess)
- **Severity:** High
- **Vulnerability Type:** SSRF
- **Platform:** HackerOne
- **Program:** Lichess
- **Bounty:** $500+
- **Description:** An SSRF vulnerability in Lichess allowed attackers to access AWS EC2 metadata by making the server issue requests to the metadata endpoint at 169.254.169.254.
- **How It Was Found:** Testing URL input fields with cloud metadata endpoints.
- **Impact:** Access to AWS instance metadata including IAM credentials and configuration data.
- **Key Takeaway:** Even open-source projects hosted on cloud infrastructure can have SSRF vulnerabilities. The AWS metadata endpoint (169.254.169.254) should always be tested in SSRF scenarios.
- **Source:** https://hackerone.com/reports/3165242

### 11. Blind SSRF in Firefox Profiler (Mozilla)
- **Severity:** Medium
- **Vulnerability Type:** Blind SSRF
- **Platform:** HackerOne / Bugzilla
- **Program:** Mozilla
- **Bounty:** $500+
- **Description:** A blind SSRF vulnerability was discovered in Firefox Profiler (profiler.firefox.com) where the server could be made to issue requests to arbitrary internal endpoints.
- **How It Was Found:** Testing profile data import/fetch features for SSRF.
- **Impact:** Internal network reconnaissance of Mozilla's infrastructure.
- **Key Takeaway:** Developer tools and profiling applications that fetch remote data are potential SSRF targets.
- **Source:** https://bugzilla.mozilla.org/show_bug.cgi?id=1937770

### 12. Blind SSRF on EXNESS Trading Platform
- **Severity:** Medium
- **Vulnerability Type:** Blind SSRF
- **Platform:** HackerOne
- **Program:** EXNESS
- **Bounty:** $500+
- **Description:** A blind SSRF was found on the EXNESS trading platform where server-side requests could be triggered to arbitrary destinations.
- **How It Was Found:** Testing various input points that accept URLs using out-of-band detection.
- **Impact:** Internal network scanning of a financial trading platform's infrastructure.
- **Key Takeaway:** Financial platforms are high-value targets for SSRF because internal network access could lead to trading system compromise.
- **Source:** https://hackerone.com/reports/1832494

### 13. Blind SSRF in Horizon-Heat (Mail.ru)
- **Severity:** Medium
- **Vulnerability Type:** Blind SSRF
- **Platform:** HackerOne
- **Program:** Mail.ru
- **Bounty:** $2,500
- **Description:** A blind SSRF was found in Mail.ru's cloud computing service (Horizon) through external YAML template resource definitions. The YAML parsing would fetch external resources.
- **How It Was Found:** Testing YAML input/template features with URLs pointing to controlled servers.
- **Impact:** Access to internal cloud infrastructure of Mail.ru.
- **Key Takeaway:** YAML parsing features that support external references (like !include or resource URLs) are SSRF vectors. Test YAML input fields with external URLs.
- **Source:** https://hackerone.com/reports/893856

### 14. Blind SSRF on New Relic Synthetics
- **Severity:** Medium
- **Vulnerability Type:** Blind SSRF
- **Platform:** HackerOne
- **Program:** New Relic
- **Bounty:** $500+
- **Description:** A blind SSRF in New Relic's Synthetics monitoring feature could be used to obtain sensitive data about internal servers. The monitoring checks could be directed at internal endpoints.
- **How It Was Found:** Testing synthetic monitoring URL configuration with internal addresses.
- **Impact:** Internal network scanning and potential data exfiltration from New Relic's infrastructure.
- **Key Takeaway:** Monitoring and health-check features that accept URLs are natural SSRF vectors because their entire purpose is to fetch URLs.
- **Source:** https://hackerone.com/reports/141304

### 15. SSRF to Read AWS Metadata (Mail.ru)
- **Severity:** High
- **Vulnerability Type:** SSRF
- **Platform:** HackerOne
- **Program:** Mail.ru
- **Bounty:** $2,500
- **Description:** An SSRF vulnerability in Mail.ru's infrastructure allowed reading AWS metadata including access keys and tokens from the EC2 metadata endpoint.
- **How It Was Found:** Testing URL-fetching features with the AWS metadata IP (169.254.169.254).
- **Impact:** Full AWS credential disclosure for the affected instance.
- **Key Takeaway:** AWS IMDSv1 is particularly vulnerable to SSRF because it requires no authentication token. Check if targets use IMDSv1 vs IMDSv2 - v1 is easier to exploit.
- **Source:** Referenced in Mail.ru HackerOne disclosures

### 16. SSRF Escalation to RCE on AWS (Blog Writeup)
- **Severity:** Critical
- **Vulnerability Type:** SSRF to RCE
- **Platform:** Private Program
- **Program:** Undisclosed
- **Bounty:** $10,000+
- **Description:** A researcher documented escalating an SSRF vulnerability to full RCE on AWS infrastructure. The SSRF was used to access AWS metadata, retrieve IAM credentials, and then use those credentials to access other AWS services including Lambda and EC2.
- **How It Was Found:** Starting with a basic SSRF, then systematically escalating by accessing cloud metadata, extracting credentials, and using AWS CLI to interact with the compromised account.
- **Impact:** Full AWS account compromise, access to all data and services in the account.
- **Key Takeaway:** SSRF in cloud environments should always be escalated. After getting metadata, try to use extracted credentials with AWS CLI to list S3 buckets, EC2 instances, Lambda functions, etc.
- **Source:** https://hg8.sh/posts/bugbounty/ssrf-to-rce-aws/

### 17. Potential SSRF and Disclosure of Credentials (Shopify)
- **Severity:** High
- **Vulnerability Type:** SSRF with Credential Disclosure
- **Platform:** HackerOne
- **Program:** Shopify
- **Bounty:** $1,000+
- **Description:** A potential SSRF vulnerability was found in Shopify that could lead to disclosure of internal credentials and sensitive configuration data.
- **How It Was Found:** Testing server-side URL fetching functionality for SSRF with various internal endpoints.
- **Impact:** Credential disclosure from Shopify's internal infrastructure.
- **Key Takeaway:** When exploiting SSRF, always try to access configuration endpoints, environment variable pages, and internal service discovery endpoints in addition to cloud metadata.
- **Source:** https://hackerone.com/reports/382612

### 18. SSRF Worth $4,913 (Highest Bounty Writeup)
- **Severity:** Critical
- **Vulnerability Type:** SSRF
- **Platform:** Private Program
- **Program:** Undisclosed (via Medium writeup)
- **Bounty:** $4,913
- **Description:** A researcher documented finding an SSRF vulnerability that was their highest bounty ever. The SSRF allowed access to internal services and cloud metadata.
- **How It Was Found:** Systematic testing of URL input parameters, using various bypass techniques including URL encoding, IP address formats, and redirect chains.
- **Impact:** Access to internal services and cloud metadata with credential exposure.
- **Key Takeaway:** Persistence in SSRF testing pays off. Try multiple bypass techniques: decimal IP, hex IP, IPv6, URL encoding, 303 redirects, DNS rebinding.
- **Source:** https://medium.com/techfenix/ssrf-server-side-request-forgery-worth-4913-my-highest-bounty-ever-7d733bb368cb

### 19. SSRF via 303 Redirect to AWS Metadata
- **Severity:** High
- **Vulnerability Type:** SSRF (Filter Bypass)
- **Platform:** HackerOne
- **Program:** Various
- **Bounty:** Varies
- **Description:** Researchers bypassed SSRF protections by using 303 Redirect responses to redirect the server's request to the AWS metadata endpoint. The application validated the initial URL but followed redirects to internal addresses.
- **How It Was Found:** Setting up a controlled server that returns 303 redirects to internal/metadata endpoints when the target server fetches the URL.
- **Impact:** Cloud metadata access despite SSRF protections being in place.
- **Key Takeaway:** Redirect-based SSRF bypass is extremely common. Set up a server that redirects to internal endpoints. Test with 301, 302, 303, 307, and 308 redirect codes.
- **Source:** Referenced in multiple SSRF writeups

### 20. SSRF on Internal Server Data Access (DoD)
- **Severity:** High
- **Vulnerability Type:** SSRF
- **Platform:** HackerOne
- **Program:** U.S. Department of Defense
- **Bounty:** N/A (VDP)
- **Description:** An SSRF vulnerability on a DoD system allowed access to internal server data, potentially exposing sensitive military/government information.
- **How It Was Found:** Testing URL parameters on DoD web applications for SSRF.
- **Impact:** Access to internal DoD infrastructure and potentially classified or sensitive data.
- **Key Takeaway:** Government VDP programs don't pay bounties but provide valuable recognition and legal safe harbor. SSRF on government systems is particularly impactful.
- **Source:** https://hackerone.com/reports/326040

---

## SSRF Hunting Methodology Summary

### Tools Commonly Used
- **Burp Collaborator / interactsh** - Out-of-band detection for blind SSRF
- **SSRFmap** - Automated SSRF exploitation tool
- **Gopherus** - Generate gopher payloads for SSRF exploitation
- **rbndr.us / singularity** - DNS rebinding for SSRF bypass
- **Nuclei** - Template-based scanner with SSRF templates

### Common SSRF Locations
1. Webhook URLs
2. PDF/document generation features
3. Screenshot/thumbnail generators
4. Import/export functionality (URL-based)
5. Image/file URL fetching
6. Integration configuration (Slack webhooks, etc.)
7. YAML/XML parsing with external references
8. Monitoring/health-check URL configuration
9. Social media preview/unfurling features
10. API proxy endpoints

### Key Cloud Metadata Endpoints
- **AWS:** http://169.254.169.254/latest/meta-data/
- **GCP:** http://metadata.google.internal/computeMetadata/v1/
- **Azure:** http://169.254.169.254/metadata/instance
- **DigitalOcean:** http://169.254.169.254/metadata/v1/

### SSRF Bypass Techniques
- Decimal IP: http://2130706433 (127.0.0.1)
- Hex IP: http://0x7f000001
- Octal IP: http://0177.0.0.1
- IPv6: http://[::1]
- URL encoding: http://%31%32%37%2e%30%2e%30%2e%31
- DNS rebinding
- Redirect chains (301/302/303/307/308)
- URL parser differentials (@, #, ?, etc.)
- CNAME/A record pointing to internal IPs

---

## Additional Reports (Expanded Collection)

### 21. SSRF via Expense Report on Lyft
- **Severity**: High
- **Bounty**: Not disclosed
- **Program**: Lyft
- **Platform**: HackerOne
- **Description**: An SSRF was found through Lyft's expense report functionality. The expense report feature processed URLs or document references server-side, allowing the researcher to make internal requests from Lyft's infrastructure.
- **How Found**: Testing expense report submission features for URL-based inputs that trigger server-side fetching.
- **Impact**: Internal network access from Lyft's production infrastructure, potential access to ride data and payment systems.
- **Key Takeaway**: Financial and expense-related features that process documents or URLs are SSRF targets. Expense reports, invoices, and receipt processing often fetch external resources.
- **Source**: https://hackerone.com/reports/885975

### 22. Full Response SSRF via Google Drive (Dropbox)
- **Severity**: Critical
- **Bounty**: $17,576
- **Program**: Dropbox
- **Platform**: HackerOne
- **Description**: A full-response SSRF was found in Dropbox's Google Drive integration. By manipulating the Google Drive import functionality, the researcher could make the server fetch arbitrary URLs and return the full response body.
- **How Found**: Testing file import features from Google Drive and manipulating the source URL to point to internal services.
- **Impact**: Full read access to internal services via response body, including cloud metadata and internal APIs.
- **Key Takeaway**: Cloud-to-cloud integrations (Google Drive, OneDrive, Dropbox imports) are high-value SSRF targets. Full-response SSRF is significantly more valuable than blind SSRF.
- **Source**: https://hackerone.com/reports/1406938

### 23. SSRF on Project Import via remote_attachment_url (GitLab) - Full Details
- **Severity**: Critical
- **Bounty**: $10,000
- **Program**: GitLab
- **Platform**: HackerOne
- **Description**: An SSRF was found in GitLab's project import via the remote_attachment_url parameter on a Note object. The import functionality fetched remote attachments without proper URL validation, enabling access to internal services.
- **How Found**: Crafting a project export file with a malicious remote_attachment_url in a Note object and importing it into GitLab.
- **Impact**: Full read SSRF allowing access to internal GitLab infrastructure and cloud metadata.
- **Key Takeaway**: Project import/export features that process serialized data with URL references are prime SSRF vectors. Analyze the export file format for URL fields.
- **Source**: https://hackerone.com/reports/826361

### 24. Server-Side Request Forgery Mitigation Bypass (GitLab)
- **Severity**: High
- **Bounty**: Not disclosed
- **Program**: GitLab
- **Platform**: HackerOne
- **Description**: A bypass was found for GitLab's SSRF mitigation controls. The researcher circumvented the URL validation and IP blocking mechanisms to access internal services.
- **How Found**: Analyzing GitLab's SSRF protection implementation and testing various bypass techniques including IP encoding, DNS rebinding, and URL parser differentials.
- **Impact**: Access to internal GitLab services despite SSRF protections being in place.
- **Key Takeaway**: SSRF protections based on URL validation can often be bypassed. Test with decimal IP, hex IP, IPv6 mapping, URL encoding, and DNS rebinding.
- **Source**: https://hackerone.com/reports/632101

### 25. SSRF and LFR via city-mobil.ru (Mail.ru)
- **Severity**: High
- **Bounty**: Not disclosed
- **Program**: Mail.ru
- **Platform**: HackerOne
- **Description**: Both SSRF and Local File Read (LFR) were found on Mail.ru's city-mobil.ru taxi service. The SSRF could be used to read local files on the server in addition to making internal network requests.
- **How Found**: Testing URL-handling features on the taxi service for both SSRF (http:// URLs) and LFR (file:// URLs).
- **Impact**: Local file system access and internal network reconnaissance on Mail.ru's taxi service infrastructure.
- **Key Takeaway**: When testing SSRF, always try the file:// protocol in addition to http://. Local file read can be even more impactful than network SSRF.
- **Source**: https://hackerone.com/reports/748123

### 26. Blind SSRF in Matrix preview_link API (Reddit)
- **Severity**: High
- **Bounty**: $6,000
- **Program**: Reddit
- **Platform**: HackerOne
- **Description**: A blind SSRF was found in Reddit's Matrix chat integration through the preview_link API. The link preview feature made server-side requests to generate previews without proper URL validation.
- **How Found**: Testing the link preview/unfurling functionality in Reddit's Matrix-based chat with URLs pointing to internal services.
- **Impact**: Access to Reddit's internal services through the Matrix integration.
- **Key Takeaway**: Link preview and URL unfurling features are classic SSRF vectors. Any feature that generates a thumbnail or preview of a URL is worth testing.
- **Source**: https://hackerone.com/reports/1960765

### 27. SSRF Leaking Internal Google Cloud Data via Upload (Vimeo)
- **Severity**: High
- **Bounty**: Not disclosed
- **Program**: Vimeo
- **Platform**: HackerOne
- **Description**: An SSRF through Vimeo's upload functionality leaked internal Google Cloud data including SSH keys and other cloud metadata. The upload handler fetched URLs server-side without proper validation.
- **How Found**: Testing upload features with URLs pointing to Google Cloud metadata endpoints (metadata.google.internal).
- **Impact**: Exposure of SSH keys and Google Cloud metadata, potentially enabling further infrastructure compromise.
- **Key Takeaway**: Google Cloud metadata uses a different endpoint (metadata.google.internal) than AWS. Always test platform-specific metadata endpoints based on the target's cloud provider.
- **Source**: https://hackerone.com/reports/549882

### 28. Full Read SSRF in Evernote
- **Severity**: High
- **Bounty**: Not disclosed
- **Program**: Evernote
- **Platform**: HackerOne
- **Description**: A full-read SSRF was found on www.evernote.com that could leak AWS metadata and perform local file inclusion. The SSRF returned complete response bodies from internal requests.
- **How Found**: Testing Evernote's note rendering and attachment handling for URL fetching that returned full responses.
- **Impact**: AWS credential exposure and local file access on Evernote's servers, potentially compromising user note data.
- **Key Takeaway**: Full-read SSRF is the gold standard - you can see the response. Prioritize finding SSRFs where the response is returned or reflected.
- **Source**: https://hackerone.com/reports/1189367

### 29. SSRF in GraphQL Query (EXNESS)
- **Severity**: High
- **Bounty**: $3,000
- **Program**: EXNESS
- **Platform**: HackerOne
- **Description**: An SSRF was found in EXNESS's GraphQL API endpoint. The GraphQL query processing allowed making server-side requests to arbitrary URLs through specially crafted queries.
- **How Found**: Testing GraphQL queries for URL-type fields that trigger server-side fetching, and mutation endpoints that process URL inputs.
- **Impact**: Internal network access on a financial trading platform, potentially exposing trading systems and customer financial data.
- **Key Takeaway**: GraphQL APIs with URL-type fields or file upload mutations are SSRF targets. Test all URL inputs in GraphQL schemas.
- **Source**: https://hackerone.com/reports/1864188

### 30. Full Read SSRF on GitLab's Internal Grafana
- **Severity**: High
- **Bounty**: Not disclosed
- **Program**: GitLab
- **Platform**: HackerOne
- **Description**: A full-read SSRF was found that allowed accessing GitLab's internal Grafana monitoring dashboard. The SSRF provided complete response data from the internal monitoring system.
- **How Found**: Discovering an SSRF vector and targeting known internal monitoring endpoints (Grafana, Prometheus, Kibana).
- **Impact**: Access to GitLab's internal monitoring data, exposing infrastructure metrics, error rates, and deployment information.
- **Key Takeaway**: After finding SSRF, target common internal monitoring tools: Grafana (:3000), Prometheus (:9090), Kibana (:5601), Jenkins (:8080).
- **Source**: https://hackerone.com/reports/878779

### 31. Unauthenticated SSRF in Jira Leading to RCE in Confluence (QIWI)
- **Severity**: Critical
- **Bounty**: Not disclosed
- **Program**: QIWI
- **Platform**: HackerOne
- **Description**: An unauthenticated SSRF in QIWI's Jira instance was chained with a Confluence vulnerability to achieve Remote Code Execution. The SSRF was used to reach internal Confluence instances that were not publicly accessible.
- **How Found**: Finding an unauthenticated SSRF in Jira and using it to access internal Confluence instances, then exploiting a known Confluence RCE vulnerability.
- **Impact**: Full remote code execution on internal Confluence servers, access to internal knowledge base and documentation.
- **Key Takeaway**: SSRF can be chained with vulnerabilities in internal services. After finding SSRF, enumerate internal services and test them for known CVEs.
- **Source**: https://hackerone.com/reports/713900

### 32. SSRF on DuckDuckGo /iu/ Endpoint
- **Severity**: Medium
- **Bounty**: Not disclosed
- **Program**: DuckDuckGo
- **Platform**: HackerOne
- **Description**: An SSRF was found on DuckDuckGo's image proxy endpoint (/iu/). The image proxy service fetched URLs server-side without adequate validation.
- **How Found**: Testing DuckDuckGo's image proxy URL parameter with internal addresses and cloud metadata endpoints.
- **Impact**: Internal network access from DuckDuckGo's infrastructure through the image proxy.
- **Key Takeaway**: Image proxy services are natural SSRF targets because their core function is to fetch URLs. Look for /proxy, /image, /thumbnail, /iu/ endpoints.
- **Source**: https://hackerone.com/reports/398641

### 33. External SSRF and LFR via FFmpeg HLS Processing (TikTok)
- **Severity**: High
- **Bounty**: $2,727
- **Program**: TikTok
- **Platform**: HackerOne
- **Description**: An SSRF and local file read were achieved through TikTok's video upload by exploiting FFmpeg's HLS (HTTP Live Streaming) processing. Malicious HLS playlists could reference internal URLs or local files.
- **How Found**: Crafting malicious M3U8 HLS playlist files that reference internal URLs and local files, then uploading them as video content.
- **Impact**: Local file read and internal network access on TikTok's video processing infrastructure.
- **Key Takeaway**: Video processing with FFmpeg is a well-known SSRF vector. Craft malicious HLS playlists (.m3u8) with internal URLs to exploit FFmpeg-based SSRF.
- **Source**: https://hackerone.com/reports/1062888

### 34. SSRF via Office File Thumbnails (Slack)
- **Severity**: High
- **Bounty**: $4,000
- **Program**: Slack
- **Platform**: HackerOne
- **Description**: An SSRF was found through Slack's Office file thumbnail generation. When generating thumbnails for uploaded Office documents, the server fetched external resources referenced in the document.
- **How Found**: Creating Office documents (DOCX, XLSX) with external resource references (images, OLE objects) pointing to internal endpoints and uploading them to Slack.
- **Impact**: Internal network access from Slack's file processing infrastructure.
- **Key Takeaway**: Document thumbnail/preview generation for Office files is an SSRF vector. Office documents can reference external resources that are fetched server-side.
- **Source**: https://hackerone.com/reports/671935

### 35. SSRF on music.line.me via getXML.php (LY Corporation)
- **Severity**: High
- **Bounty**: $4,500
- **Program**: LY Corporation (LINE)
- **Platform**: HackerOne
- **Description**: An SSRF was found on LINE's music service through the getXML.php endpoint. The endpoint fetched XML content from user-supplied URLs without proper validation.
- **How Found**: Testing the getXML.php endpoint with URLs pointing to internal services and cloud metadata.
- **Impact**: Internal network access on LINE's music service infrastructure.
- **Key Takeaway**: PHP endpoints that fetch remote content (getXML.php, fetchURL.php, proxy.php) are obvious SSRF targets. Look for descriptively named endpoints.
- **Source**: https://hackerone.com/reports/746024

### 36. Unauthenticated Blind SSRF in GitLab OAuth Jira Authorization
- **Severity**: High
- **Bounty**: $4,000
- **Program**: GitLab
- **Platform**: HackerOne
- **Description**: An unauthenticated blind SSRF was found in GitLab's OAuth authorization controller for Jira integration. No authentication was required to trigger the SSRF.
- **How Found**: Testing OAuth authorization endpoints for Jira integration with arbitrary URLs, discovering that no authentication was required.
- **Impact**: Unauthenticated internal network scanning through GitLab's Jira OAuth integration.
- **Key Takeaway**: Unauthenticated SSRF is more impactful than authenticated. OAuth and integration endpoints sometimes skip authentication checks.
- **Source**: https://hackerone.com/reports/398799

### 37. SSRF Chained to Hit Internal Host Leading to Internal Image Read (PlayStation)
- **Severity**: High
- **Bounty**: $1,000
- **Program**: PlayStation
- **Platform**: HackerOne
- **Description**: An initial SSRF was chained to hit an internal host, which itself had another SSRF that allowed reading internal images. This double-SSRF chain accessed otherwise unreachable internal resources.
- **How Found**: Using the first SSRF to discover internal services, then finding a second SSRF on an internal service to pivot deeper into the network.
- **Impact**: Access to internal images and resources on PlayStation's infrastructure through a chained SSRF.
- **Key Takeaway**: SSRF can be chained - use the first SSRF to discover internal services, then pivot through internal services that have their own SSRF vulnerabilities.
- **Source**: https://hackerone.com/reports/826097

### 38. SSRF on PlayStation Image Renderer
- **Severity**: High
- **Bounty**: $1,000
- **Program**: PlayStation
- **Platform**: HackerOne
- **Description**: An SSRF was found in PlayStation's image rendering service. The renderer fetched images from user-supplied URLs without proper validation.
- **How Found**: Testing image URL parameters in PlayStation's web services for SSRF.
- **Impact**: Internal network access through PlayStation's image rendering infrastructure.
- **Key Takeaway**: Image rendering and processing services are frequent SSRF targets because they inherently need to fetch remote resources.
- **Source**: https://hackerone.com/reports/811136

### 39. Injection of git config Settings Leading to SSRF (GitLab)
- **Severity**: High
- **Bounty**: $3,000
- **Program**: GitLab
- **Platform**: HackerOne
- **Description**: By injecting http.<url>.* git configuration settings, an attacker could make GitLab's git client send requests to arbitrary internal endpoints, achieving SSRF through git's HTTP transport.
- **How Found**: Testing git configuration injection through GitLab features that accept git config parameters.
- **Impact**: SSRF through git's HTTP client, allowing access to internal services from GitLab's git processing.
- **Key Takeaway**: Git configuration injection can lead to SSRF through git's HTTP transport. Test for config injection in any service that runs git operations.
- **Source**: https://hackerone.com/reports/855276

### 40. SSRF in EXNESS Affiliates Platform
- **Severity**: Medium
- **Bounty**: Not disclosed
- **Program**: EXNESS
- **Platform**: HackerOne
- **Description**: A blind SSRF was found on EXNESS's affiliate platform that allowed internal network enumeration. The SSRF could scan internal ports and identify running services.
- **How Found**: Testing URL input fields on the affiliate platform with internal IP addresses and port combinations using out-of-band detection.
- **Impact**: Internal network enumeration of EXNESS's financial platform infrastructure.
- **Key Takeaway**: Even blind SSRF is valuable for network enumeration. Use timing-based or out-of-band techniques to map internal network topology.
- **Source**: https://hackerone.com/reports/1832494

### 41. XXE Injection Through SVG Leading to SSRF (Zivver)
- **Severity**: High
- **Bounty**: Not disclosed
- **Program**: Zivver
- **Platform**: HackerOne
- **Description**: An XXE injection through SVG image upload was used to achieve SSRF. The SVG parser processed XML external entities, allowing the attacker to make the server fetch internal URLs.
- **How Found**: Uploading SVG files with XXE payloads (<!DOCTYPE> with external entity definitions) through the image upload feature.
- **Impact**: Internal network access and potential file read through XXE-to-SSRF chain.
- **Key Takeaway**: SVG files are XML-based and can contain XXE payloads. Any SVG upload or processing feature should be tested for XXE-to-SSRF.
- **Source**: https://hackerone.com/reports/897244

### 42. Server-Side Request Forgery via Game Export API (Lichess) - Full Details
- **Severity**: High
- **Bounty**: Not disclosed
- **Program**: Lichess
- **Platform**: HackerOne
- **Description**: An SSRF was found in Lichess's game export API endpoint. The API processed URLs for game data export, allowing the attacker to make the server request internal resources.
- **How Found**: Testing the game export API parameters for URL injection that triggers server-side fetching.
- **Impact**: Access to internal Lichess infrastructure and cloud metadata.
- **Key Takeaway**: API export features that generate files or fetch data from URLs are SSRF targets.
- **Source**: https://hackerone.com/reports/3165242

### 43. SSRF in Autodesk Rendering Leading to Account Takeover
- **Severity**: Critical
- **Bounty**: Not disclosed
- **Program**: Autodesk
- **Platform**: HackerOne
- **Description**: An SSRF in Autodesk's rendering service was escalated to account takeover. The rendering service fetched resources from attacker-controlled URLs, allowing credential theft.
- **How Found**: Testing Autodesk's cloud rendering features for SSRF by submitting rendering jobs with malicious resource URLs.
- **Impact**: Full account takeover of Autodesk users through SSRF-based credential theft.
- **Key Takeaway**: 3D rendering and design tool cloud services that fetch remote assets are valuable SSRF targets. Escalate SSRF to credential theft for maximum impact.
- **Source**: https://hackerone.com/reports/3024673

### 44. DNS Rebinding SSRF in Burp Suite MCP Server (PortSwigger)
- **Severity**: High
- **Bounty**: $2,000
- **Program**: PortSwigger Web Security
- **Platform**: HackerOne
- **Description**: A DNS rebinding attack was used to achieve SSRF in Burp Suite's MCP Server, enabling internal network access through the send_http1_request tool.
- **How Found**: Using DNS rebinding techniques to bypass IP-based SSRF protections in Burp Suite's server component.
- **Impact**: Access to internal network from Burp Suite's MCP Server, potentially exposing security testing data.
- **Key Takeaway**: Even security tools can be vulnerable to SSRF. DNS rebinding is an effective technique against tools that validate IPs at DNS resolution time.
- **Source**: https://hackerone.com/reports/3176157

### 45. SSRF in couriers.indrive.com File Storage
- **Severity**: High
- **Bounty**: Not disclosed
- **Program**: inDrive
- **Platform**: HackerOne
- **Description**: An SSRF was found in inDrive's courier service file storage API. The file storage endpoint fetched content from user-supplied URLs without proper validation.
- **How Found**: Testing the file upload/storage API with URLs pointing to internal services instead of legitimate file locations.
- **Impact**: Internal network access from inDrive's courier service infrastructure.
- **Key Takeaway**: File storage APIs that accept URLs for remote file import are natural SSRF targets.
- **Source**: https://hackerone.com/reports/2300358

### 46. SSRF in clients.city-mobil.ru (Mail.ru)
- **Severity**: High
- **Bounty**: $1,500
- **Program**: Mail.ru
- **Platform**: HackerOne
- **Description**: An SSRF was found in Mail.ru's city-mobil.ru taxi service client API. The vulnerability allowed making internal requests from the taxi platform's infrastructure.
- **How Found**: Testing API endpoints on the taxi platform for URL-based parameters that trigger server-side requests.
- **Impact**: Internal network access on Mail.ru's taxi service, potentially exposing driver and rider data.
- **Key Takeaway**: Ride-sharing and delivery platforms have extensive APIs that may contain SSRF vectors, especially in features handling map tiles, images, or external data.
- **Source**: https://hackerone.com/reports/712103

### 47. Server-Side Request Forgery in Webhook Functionality (HackerOne)
- **Severity**: High
- **Bounty**: $2,500
- **Program**: HackerOne
- **Platform**: HackerOne
- **Description**: An SSRF was found in HackerOne's webhook functionality. The webhook delivery mechanism could be exploited to make requests to internal services.
- **How Found**: Configuring webhook URLs to point to internal services and monitoring the server-side request behavior.
- **Impact**: Internal network access from HackerOne's production infrastructure.
- **Key Takeaway**: Webhook features are inherently SSRF-prone because they send HTTP requests to user-supplied URLs. Always test webhook URLs with internal addresses.
- **Source**: https://hackerone.com/reports/2301565

### 48. Full Read SSRF via Lark Docs Import Feature
- **Severity**: High
- **Bounty**: $5,000
- **Program**: Lark Technologies
- **Platform**: HackerOne
- **Description**: A full-read SSRF was found through Lark Docs' "import as docs" feature. The import functionality fetched remote content and returned it, providing full response data.
- **How Found**: Testing the document import feature with URLs pointing to internal services and cloud metadata endpoints.
- **Impact**: Full read access to internal services and cloud metadata through Lark's document import functionality.
- **Key Takeaway**: Document import features that convert external content into documents can provide full-read SSRF because the content is displayed to the user.
- **Source**: https://hackerone.com/reports/1409727

### 49. Kafka Connect RCE via SSRF to Internal Jolokia (Aiven)
- **Severity**: Critical
- **Bounty**: $5,000
- **Program**: Aiven Ltd
- **Platform**: HackerOne
- **Description**: RCE was achieved through Kafka Connect by leveraging file upload via SQLite JDBC driver and SSRF to internal Jolokia JMX interface. The SSRF enabled access to the internal management interface.
- **How Found**: Chaining Kafka Connect sink connectors with SSRF to access Jolokia, then using Jolokia to achieve code execution.
- **Impact**: Remote code execution on Aiven's managed Kafka infrastructure.
- **Key Takeaway**: Managed service platforms with complex middleware (Kafka, Redis, RabbitMQ) can have SSRF vectors through connector and integration features.
- **Source**: https://hackerone.com/reports/1547877

### 50. Half-Blind SSRF in Kubernetes Cloud Controller Manager
- **Severity**: High
- **Bounty**: $5,000
- **Program**: Kubernetes
- **Platform**: HackerOne
- **Description**: A half-blind SSRF was found in Kubernetes' cloud controller manager that could be upgraded to complete SSRF (fully crafted HTTP requests) in vendor-managed Kubernetes services.
- **How Found**: Analyzing Kubernetes cloud controller manager code for URL handling vulnerabilities in cloud provider integrations.
- **Impact**: Full SSRF capability in managed Kubernetes environments, potentially accessing cloud metadata and internal services.
- **Key Takeaway**: Container orchestration platforms (Kubernetes, Docker Swarm) have SSRF vectors in their cloud provider integrations and controller components.
- **Source**: https://hackerone.com/reports/776017

### 51. SSRF in Slack API via Slash Commands with Protection Bypass
- **Severity**: High
- **Bounty**: Not disclosed
- **Program**: Slack
- **Platform**: HackerOne
- **Description**: An SSRF was found in Slack's API through slash commands that bypassed existing SSRF protections. The slash command processing made server-side requests that could target internal services.
- **How Found**: Testing Slack slash commands with URLs pointing to internal services and finding ways to bypass the SSRF protection mechanisms.
- **Impact**: Internal network access from Slack's API infrastructure.
- **Key Takeaway**: Slash commands and chat bot features that fetch URLs are SSRF targets. Custom integrations and bots may bypass centralized SSRF protections.
- **Source**: https://hackerone.com/reports/381129

### 52. SVG Server-Side Request Forgery (Shopify)
- **Severity**: Medium
- **Bounty**: $500
- **Program**: Shopify
- **Platform**: HackerOne
- **Description**: An SSRF was achieved through SVG file upload on Shopify. The SVG processing fetched external resources referenced in the SVG file's XML.
- **How Found**: Uploading SVG files with external resource references (xlink:href, foreignObject) pointing to internal services.
- **Impact**: Internal network access from Shopify's SVG processing infrastructure.
- **Key Takeaway**: SVG files can reference external resources through multiple mechanisms (xlink:href, use, image, foreignObject). Test all SVG-related features for SSRF.
- **Source**: https://hackerone.com/reports/223203

### 53. Blind SSRF in Rockstar Games Emblem Editor
- **Severity**: High
- **Bounty**: $1,500
- **Program**: Rockstar Games
- **Platform**: HackerOne
- **Description**: A blind SSRF was found in Rockstar Games' emblem editor feature. The emblem creation process fetched external resources that could be directed at internal endpoints.
- **How Found**: Testing the emblem editor's image import and SVG processing with URLs pointing to internal services using out-of-band detection.
- **Impact**: Internal network scanning of Rockstar Games' infrastructure.
- **Key Takeaway**: Game platforms with custom content creation tools (emblem editors, level editors, avatar creators) often fetch external resources and are SSRF targets.
- **Source**: https://hackerone.com/reports/265050

### 54. LFI and SSRF via XXE in Emblem Editor (Rockstar Games)
- **Severity**: High
- **Bounty**: $1,500
- **Program**: Rockstar Games
- **Platform**: HackerOne
- **Description**: Both Local File Inclusion and SSRF were achieved through XXE injection in Rockstar Games' emblem editor. The XML parser in the editor processed external entities.
- **How Found**: Submitting emblem data with XXE payloads that reference local files and internal network endpoints.
- **Impact**: Local file read and internal network access on Rockstar Games' servers.
- **Key Takeaway**: XXE is a gateway to both SSRF and LFI. Any XML processing feature should be tested with XXE payloads.
- **Source**: https://hackerone.com/reports/347139

### 55. SMB SSRF in Emblem Editor Exposing Domain Credentials (Rockstar Games)
- **Severity**: Critical
- **Bounty**: $1,500
- **Program**: Rockstar Games
- **Platform**: HackerOne
- **Description**: An SMB-based SSRF in Rockstar Games' emblem editor exposed Windows domain credentials. The server followed UNC paths, sending NTLM authentication hashes to an attacker-controlled SMB server.
- **How Found**: Using UNC paths (\\\\attacker-server\\share) in the emblem editor to trigger SMB authentication and capture NTLM hashes with Responder.
- **Impact**: Windows domain credential exposure, potentially enabling lateral movement across Rockstar's internal network.
- **Key Takeaway**: On Windows servers, test SSRF with UNC paths (\\\\) to capture NTLM hashes. Use Responder to capture authentication attempts.
- **Source**: https://hackerone.com/reports/288353

### 56. SSRF via Host Header on IBM Domain
- **Severity**: High
- **Bounty**: Not disclosed
- **Program**: IBM
- **Platform**: HackerOne
- **Description**: An SSRF was achieved through Host header manipulation on an IBM domain. The application used the Host header value to construct internal URLs, allowing access to localhost.
- **How Found**: Testing Host header injection with various internal hostnames and IP addresses.
- **Impact**: Access to localhost services on IBM's web servers through Host header manipulation.
- **Key Takeaway**: Host header injection can lead to SSRF when the application uses the Host header to construct internal URLs. Test with alternate Host header values.
- **Source**: https://hackerone.com/reports/2696271

### 57. Libuv Improper Domain Lookup Leading to SSRF (Internet Bug Bounty)
- **Severity**: High
- **Bounty**: $4,860
- **Program**: Internet Bug Bounty
- **Platform**: HackerOne
- **Description**: An improper domain lookup vulnerability in libuv (the async I/O library used by Node.js) could lead to SSRF attacks in applications using the library for DNS resolution.
- **How Found**: Source code review of libuv's DNS resolution implementation, identifying cases where domain lookups could be manipulated.
- **Impact**: SSRF in any application using the affected libuv version, including Node.js applications.
- **Key Takeaway**: Library-level vulnerabilities in DNS resolution can enable SSRF across all applications using that library. These findings have massive reach.
- **Source**: https://hackerone.com/reports/2429894

### 58. Apache HTTP Server SSRF on Windows (CVE-2024-38472)
- **Severity**: High
- **Bounty**: $4,920
- **Program**: Internet Bug Bounty
- **Platform**: HackerOne
- **Description**: An SSRF vulnerability was found in Apache HTTP Server on Windows through UNC path handling. The CVE affected Apache's handling of Windows UNC paths in URL processing.
- **How Found**: Testing Apache HTTP Server's URL handling on Windows with UNC path variations.
- **Impact**: SSRF in Apache HTTP Server installations on Windows, potentially affecting millions of servers.
- **Key Takeaway**: Windows-specific SSRF through UNC paths affects Apache and other web servers. Always test Windows-specific path handling.
- **Source**: https://hackerone.com/reports/2585385

### 59. Apache HTTP Server SSRF with mod_rewrite on Windows (CVE-2024-40898)
- **Severity**: High
- **Bounty**: $4,263
- **Program**: Internet Bug Bounty
- **Platform**: HackerOne
- **Description**: An SSRF vulnerability was found in Apache HTTP Server's mod_rewrite module in server/vhost context on Windows. The rewrite rules could be manipulated to make the server issue internal requests.
- **How Found**: Testing mod_rewrite configurations for URL manipulation that could lead to SSRF on Windows deployments.
- **Impact**: SSRF on Windows Apache installations using mod_rewrite, potentially exposing internal services.
- **Key Takeaway**: Web server modules that rewrite or proxy URLs (mod_rewrite, mod_proxy) can introduce SSRF. Test rewrite rules for URL manipulation.
- **Source**: https://hackerone.com/reports/2612028

### 60. SSRF and Secret Key Disclosure on IBM Turbonomic Endpoint
- **Severity**: High
- **Bounty**: Not disclosed
- **Program**: IBM
- **Platform**: HackerOne
- **Description**: An SSRF on IBM's Turbonomic endpoint led to secret key disclosure. The SSRF allowed accessing internal configuration endpoints that exposed API keys and secrets.
- **How Found**: Testing Turbonomic's API endpoints for SSRF and targeting internal configuration and secret management endpoints.
- **Impact**: Secret key disclosure from IBM's infrastructure management platform, potentially enabling broader access.
- **Key Takeaway**: After finding SSRF, target internal secret management endpoints, configuration APIs, and key vaults for maximum impact.
- **Source**: https://hackerone.com/reports/2697592

### 61. SSRF at Razer Payment Platform via notify_url
- **Severity**: High
- **Bounty**: $2,000
- **Program**: Razer
- **Platform**: HackerOne
- **Description**: An SSRF was found at Razer's payment platform through the notify_url parameter. The payment notification system made server-side requests to the user-supplied notification URL.
- **How Found**: Testing payment callback/notification URL parameters for SSRF during the payment flow.
- **Impact**: Internal network access from Razer's payment infrastructure.
- **Key Takeaway**: Payment notification URLs (IPN, webhooks, callbacks) are SSRF targets because payment systems must make server-side calls to these URLs.
- **Source**: https://hackerone.com/reports/777664

### 62. SSRF in Kubernetes via Hijacked Aggregated API Server
- **Severity**: High
- **Bounty**: $1,000
- **Program**: Kubernetes
- **Platform**: HackerOne
- **Description**: An SSRF was found in Kubernetes when a hijacked aggregated API server (like metrics-server) returned 30X redirect responses. The API server would follow redirects to internal endpoints.
- **How Found**: Analyzing Kubernetes API aggregation layer for redirect-following behavior when communicating with aggregated API servers.
- **Impact**: SSRF within the Kubernetes control plane, potentially accessing the kubelet API and pod metadata.
- **Key Takeaway**: Kubernetes API aggregation and service mesh architectures can have SSRF through redirect following. Test service-to-service communication for redirect-based SSRF.
- **Source**: https://hackerone.com/reports/1544133

### 63. Blind SSRF on Cloudflare Dashboard via Sentry Misconfiguration
- **Severity**: Medium
- **Bounty**: Not disclosed
- **Program**: Cloudflare
- **Platform**: HackerOne
- **Description**: A blind SSRF was found on Cloudflare's dashboard due to a Sentry error tracking misconfiguration. The Sentry DSN endpoint could be abused to make internal requests.
- **How Found**: Identifying exposed Sentry DSN endpoints and testing them for SSRF by sending crafted error reports with internal URLs.
- **Impact**: Internal network scanning of Cloudflare's infrastructure through the error tracking service.
- **Key Takeaway**: Sentry misconfigurations are a recurring SSRF vector. Look for exposed Sentry DSN endpoints on any target that uses Sentry for error tracking.
- **Source**: https://hackerone.com/reports/1467044

### 64. SSRF in Semrush Video Content Feature
- **Severity**: High
- **Bounty**: Not disclosed
- **Program**: Semrush
- **Platform**: HackerOne
- **Description**: An SSRF was found in Semrush's "Get Video Contents" feature. The feature fetched video data from user-supplied URLs without proper validation.
- **How Found**: Testing the video content fetching feature with URLs pointing to internal services and metadata endpoints.
- **Impact**: Internal network access from Semrush's video processing infrastructure.
- **Key Takeaway**: SEO and marketing tools that analyze or fetch content from URLs are prime SSRF targets because content fetching is their core function.
- **Source**: https://hackerone.com/reports/643622

### 65. SSRF via SSRF Protection Bypass Using Trailing Dot (Stripe)
- **Severity**: Medium
- **Bounty**: Not disclosed
- **Program**: Stripe
- **Platform**: HackerOne
- **Description**: An SSRF protection bypass was found in Stripe's Smokescreen proxy by using a trailing dot in domain names. The deny_list rule could be bypassed by appending a dot to blocked domains.
- **How Found**: Testing various domain name variations including trailing dots, which are valid in DNS but often not handled by deny lists.
- **Impact**: Bypass of Stripe's SSRF protections, enabling access to previously blocked internal domains.
- **Key Takeaway**: Trailing dots in domain names (e.g., internal.service.) are valid DNS and can bypass domain deny lists. Always test this simple bypass.
- **Source**: https://hackerone.com/reports/1410214

### 66. SSRF and Local File Disclosure via FFmpeg on WordPress.com
- **Severity**: High
- **Bounty**: Not disclosed
- **Program**: Automattic
- **Platform**: HackerOne
- **Description**: SSRF and local file disclosure were achieved through video upload on WordPress.com by exploiting FFmpeg's HLS processing. Malicious M3U8 playlists triggered server-side requests and file reads.
- **How Found**: Uploading crafted M3U8 HLS playlists as video content through WordPress.com's media upload.
- **Impact**: Local file read and SSRF on WordPress.com's video processing infrastructure.
- **Key Takeaway**: FFmpeg-based SSRF through HLS playlists is a well-documented attack. Any platform that processes uploaded video content may be vulnerable.
- **Source**: https://hackerone.com/reports/237381

### 67. SSRF in Functional Administrative Support Tool (DoD)
- **Severity**: High
- **Bounty**: $4,000
- **Program**: U.S. Department of Defense
- **Platform**: HackerOne
- **Description**: An SSRF was found in a DoD Functional Administrative Support Tool's PDF generator. The PDF generation feature fetched external resources, allowing SSRF to internal endpoints.
- **How Found**: Testing the PDF generation feature with internal URLs in the document content or template references.
- **Impact**: Access to internal DoD network services through the PDF generator.
- **Key Takeaway**: PDF generation features that render HTML or fetch remote resources are classic SSRF vectors. Test with internal URLs in CSS, images, and links.
- **Source**: https://hackerone.com/reports/1628209

### 68. SSRF to Read AWS Metadata on DoD System
- **Severity**: High
- **Bounty**: $1,000
- **Program**: U.S. Department of Defense
- **Platform**: HackerOne
- **Description**: An SSRF on a DoD system was used to read AWS metadata, exposing instance credentials and configuration from the EC2 metadata service.
- **How Found**: Testing URL parameters on DoD web applications with the AWS metadata endpoint (169.254.169.254).
- **Impact**: AWS credential exposure on a DoD cloud-hosted system.
- **Key Takeaway**: Government and military systems increasingly use cloud infrastructure (AWS GovCloud). The same cloud metadata attacks apply to government targets.
- **Source**: https://hackerone.com/reports/1624140

### 69. Blind SSRF in 8x8 Chat Image Check API
- **Severity**: Medium
- **Bounty**: Not disclosed
- **Program**: 8x8
- **Platform**: HackerOne
- **Description**: A blind SSRF was found in 8x8's /api/v2/chats/image-check endpoint that allowed internal port scanning. The image validation endpoint made server-side requests to check image URLs.
- **How Found**: Testing the image validation API with internal IP addresses and various ports, using response timing to determine open ports.
- **Impact**: Internal port scanning of 8x8's communication platform infrastructure.
- **Key Takeaway**: Image validation/checking APIs that verify if a URL points to a valid image are blind SSRF targets. Use timing differences to enumerate ports.
- **Source**: https://hackerone.com/reports/1875484

### 70. SSRF in Filtering Feature on relap.io (Mail.ru)
- **Severity**: Medium
- **Bounty**: Not disclosed
- **Program**: Mail.ru
- **Platform**: HackerOne
- **Description**: An SSRF was found in the filtering functionality on Mail.ru's relap.io content recommendation service. The filtering feature processed URLs that could be directed at internal services.
- **How Found**: Testing content filtering/recommendation URL parameters for SSRF.
- **Impact**: Internal network access from Mail.ru's content recommendation infrastructure.
- **Key Takeaway**: Content recommendation and filtering engines that process URLs to analyze content are SSRF targets.
- **Source**: https://hackerone.com/reports/739962

### 71. Blind SSRF in Stripo App Export via Zapier Integration
- **Severity**: Medium
- **Bounty**: Not disclosed
- **Program**: Stripo Inc
- **Platform**: HackerOne
- **Description**: A blind SSRF was found in Stripo's email template app through the export functionality when sending email messages to Zapier via missing endpoint configuration.
- **How Found**: Testing the Zapier integration export feature with controlled endpoint URLs.
- **Impact**: Internal network scanning through Stripo's Zapier integration.
- **Key Takeaway**: Third-party integrations (Zapier, IFTTT, Make) that send data to user-configured endpoints are SSRF vectors.
- **Source**: https://hackerone.com/reports/2932960

### 72. Blind SSRF on NordVPN Debug Endpoint via Sentry Misconfiguration
- **Severity**: Medium
- **Bounty**: Not disclosed
- **Program**: Nord Security
- **Platform**: HackerOne
- **Description**: A blind SSRF was found on NordVPN's debug endpoint due to a misconfigured Sentry instance. The debug/error tracking endpoint could be abused for SSRF.
- **How Found**: Discovering exposed Sentry debug endpoints and testing them for SSRF capability.
- **Impact**: Internal network scanning of NordVPN's infrastructure.
- **Key Takeaway**: VPN providers' debug endpoints are high-value targets. Sentry misconfigurations continue to be a common source of blind SSRF.
- **Source**: https://hackerone.com/reports/756149

### 73. SSRF via VCARD Photo Upload (Open-Xchange)
- **Severity**: Medium
- **Bounty**: $850
- **Program**: Open-Xchange
- **Platform**: HackerOne
- **Description**: An SSRF was found through the VCARD photo upload functionality in Open-Xchange. The VCARD processing fetched photo URLs specified in the contact card.
- **How Found**: Creating VCARD files with PHOTO properties pointing to internal URLs and importing them.
- **Impact**: Internal network access through Open-Xchange's contact import processing.
- **Key Takeaway**: Contact import features (VCARD, CSV, LDIF) that support URL-based profile photos are SSRF vectors.
- **Source**: https://hackerone.com/reports/296045

### 74. Full SSRF on Acronis Cloud
- **Severity**: High
- **Bounty**: Not disclosed
- **Program**: Acronis
- **Platform**: HackerOne
- **Description**: A full-response SSRF was found on Acronis's cloud platform, allowing the attacker to read complete responses from internal services.
- **How Found**: Testing Acronis Cloud features that handle URLs for SSRF, finding one that returns the full response body.
- **Impact**: Full read access to internal services on Acronis's backup and security cloud platform.
- **Key Takeaway**: Backup and disaster recovery platforms that handle remote URLs for backup sources are SSRF targets.
- **Source**: https://hackerone.com/reports/1241149

### 75. Unauthenticated Full-Read SSRF via Twilio Integration (Rocket.Chat)
- **Severity**: High
- **Bounty**: Not disclosed
- **Program**: Rocket.Chat
- **Platform**: HackerOne
- **Description**: An unauthenticated full-read SSRF was found through Rocket.Chat's Twilio integration. No authentication was required to exploit the SSRF, and full response data was returned.
- **How Found**: Testing Twilio integration endpoints on Rocket.Chat installations for unauthenticated SSRF.
- **Impact**: Unauthenticated access to internal services from Rocket.Chat servers, potentially affecting self-hosted installations.
- **Key Takeaway**: Self-hosted applications with third-party integrations (Twilio, Slack, SendGrid) may expose unauthenticated SSRF endpoints. Integration callbacks often lack authentication.
- **Source**: https://hackerone.com/reports/1886954

### 76. SSRF on fleet.city-mobil.ru Leading to Local File Read (Mail.ru)
- **Severity**: High
- **Bounty**: Not disclosed
- **Program**: Mail.ru
- **Platform**: HackerOne
- **Description**: An SSRF on Mail.ru's taxi fleet management system led to local file read on the server. The fleet management application processed URLs that could include file:// protocol.
- **How Found**: Testing the fleet management system's URL handling with file:// protocol to read local files.
- **Impact**: Local file access on the fleet management server, potentially exposing driver data and operational information.
- **Key Takeaway**: Always test file:// protocol in SSRF vulnerabilities. Many URL parsers support file:// which enables local file read.
- **Source**: https://hackerone.com/reports/748069

### 77. Bypassing HTML Filter in Packing Slip Template Leading to SSRF (Shopify)
- **Severity**: Medium
- **Bounty**: Not disclosed
- **Program**: Shopify
- **Platform**: HackerOne
- **Description**: An HTML filter bypass in Shopify's packing slip template led to SSRF targeting internal Kubernetes endpoints. The template rendering engine fetched resources from attacker-controlled URLs.
- **How Found**: Testing Shopify's template customization features for HTML injection that could trigger server-side resource fetching.
- **Impact**: Access to internal Kubernetes API and pod metadata from Shopify's infrastructure.
- **Key Takeaway**: Template engines that render HTML server-side can be SSRF vectors through CSS, image, and link references to internal endpoints.
- **Source**: https://hackerone.com/reports/1115139

### 78. Portainer SSRF Leading to Internal Docker API Access (Uber)
- **Severity**: High
- **Bounty**: $500
- **Program**: Uber
- **Platform**: HackerOne
- **Description**: An SSRF in Uber's Portainer instance on an internal domain led to unauthenticated access to the internal Docker API, enabling container management.
- **How Found**: Discovering an exposed Portainer instance and exploiting SSRF to access the Docker API socket.
- **Impact**: Full Docker API access allowing container creation, deletion, and code execution on Uber's internal infrastructure.
- **Key Takeaway**: Container management tools (Portainer, Rancher, Docker API) exposed via SSRF can lead to container escape and RCE.
- **Source**: https://hackerone.com/reports/366638

### 79. Full Read SSRF on Uber Internal Flyte Instance
- **Severity**: High
- **Bounty**: $2,000
- **Program**: Uber
- **Platform**: HackerOne
- **Description**: A full-read SSRF was found on Uber's internal Flyte workflow orchestration platform. The SSRF provided complete response data from internal services.
- **How Found**: Discovering an exposed Flyte instance on an Uber internal domain and testing it for SSRF.
- **Impact**: Full read access to internal Uber services through the Flyte orchestration platform.
- **Key Takeaway**: Workflow orchestration platforms (Flyte, Airflow, Argo) that execute tasks with URL inputs are SSRF targets.
- **Source**: https://hackerone.com/reports/1540906

### 80. Blind SSRF in GSA Data.gov Dashboard
- **Severity**: Medium
- **Bounty**: $300
- **Program**: GSA Bounty
- **Platform**: HackerOne
- **Description**: A blind SSRF was found on the GSA's data.gov dashboard through the Campaign/json_status endpoint. The endpoint made server-side requests to user-supplied URLs.
- **How Found**: Testing dashboard API endpoints for URL parameters that trigger server-side requests.
- **Impact**: Internal network scanning of US government data infrastructure.
- **Key Takeaway**: Government data portals and dashboards with data import/status checking features are SSRF targets.
- **Source**: https://hackerone.com/reports/895696
