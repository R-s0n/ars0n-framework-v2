# Web Application Bug Bounty Methodology

## Phase 1: Reconnaissance

### Passive Recon
1. **Subdomain Enumeration**
   - Use tools: subfinder, amass, assetfinder, findomain
   - Check certificate transparency logs (crt.sh)
   - DNS brute-forcing with custom wordlists
   - Check for subdomain takeover opportunities

2. **Technology Fingerprinting**
   - Wappalyzer / WhatWeb / BuiltWith
   - Check HTTP headers for framework indicators
   - Identify CMS, web servers, programming languages
   - Look for version-specific vulnerabilities

3. **Content Discovery**
   - Directory brute-forcing: ffuf, feroxbuster, gobuster
   - Check robots.txt, sitemap.xml, .well-known/
   - Look for backup files (.bak, .old, .swp, ~)
   - Find hidden API endpoints
   - Check JavaScript files for endpoints and secrets
   - waybackurls for historical content

4. **Information Gathering**
   - Google dorking: site:target.com filetype:pdf|doc|xlsx
   - GitHub dorking: search for leaked secrets, API keys
   - Shodan/Censys for exposed services
   - Check for S3 buckets, Azure blobs
   - LinkedIn for technology stack clues

### Active Recon
1. **Port Scanning** - nmap for open ports and services
2. **Web crawling** - Burp Spider, hakrawler, katana
3. **Parameter discovery** - Arjun, ParamSpider, x8
4. **API endpoint mapping** - Look for OpenAPI/Swagger docs

## Phase 2: Testing Areas

### Authentication Testing
- [ ] Default credentials
- [ ] Brute-force protection / rate limiting
- [ ] Password reset poisoning (Host header injection)
- [ ] Account enumeration via error messages or timing
- [ ] OAuth/OIDC misconfiguration
- [ ] JWT vulnerabilities (none algorithm, weak signing, key confusion)
- [ ] 2FA bypass techniques
- [ ] Session fixation
- [ ] Remember me functionality
- [ ] Password complexity requirements

### Authorization Testing
- [ ] IDOR - Change IDs in requests to access other users' data
- [ ] Horizontal privilege escalation
- [ ] Vertical privilege escalation (user → admin)
- [ ] Missing function-level access control
- [ ] Insecure Direct Object References in API
- [ ] Force browsing to admin pages
- [ ] Parameter manipulation for role escalation
- [ ] Mass assignment / parameter pollution

### Injection Testing
- [ ] SQL Injection (error-based, blind, time-based, UNION)
- [ ] Cross-Site Scripting (reflected, stored, DOM-based)
- [ ] Command Injection / OS Injection
- [ ] Server-Side Template Injection (SSTI)
- [ ] XML External Entity (XXE) Injection
- [ ] LDAP Injection
- [ ] NoSQL Injection
- [ ] GraphQL Injection
- [ ] CRLF Injection
- [ ] Host Header Injection
- [ ] Email Header Injection

### Client-Side Testing
- [ ] Cross-Site Scripting (XSS)
- [ ] Cross-Site Request Forgery (CSRF)
- [ ] Clickjacking
- [ ] Open Redirect
- [ ] CORS Misconfiguration
- [ ] WebSocket security
- [ ] PostMessage vulnerabilities
- [ ] DOM clobbering
- [ ] Prototype pollution

### Business Logic Testing
- [ ] Price manipulation
- [ ] Coupon/discount abuse
- [ ] Race conditions (TOCTOU)
- [ ] Workflow bypass
- [ ] Feature abuse
- [ ] Integer overflow/underflow
- [ ] Negative quantity/amount
- [ ] Currency rounding issues

### File Handling
- [ ] File upload vulnerabilities (webshell, XXE via SVG/DOCX)
- [ ] Path traversal / LFI / RFI
- [ ] File inclusion
- [ ] Unrestricted file download

### Server-Side
- [ ] SSRF (Server-Side Request Forgery)
- [ ] Remote Code Execution
- [ ] Insecure Deserialization
- [ ] Race Conditions
- [ ] Memory leaks / Information disclosure
- [ ] DNS rebinding

### API-Specific
- [ ] Broken Object Level Authorization (BOLA)
- [ ] Broken Authentication
- [ ] Excessive Data Exposure
- [ ] Lack of Resources & Rate Limiting
- [ ] Broken Function Level Authorization
- [ ] Mass Assignment
- [ ] Security Misconfiguration
- [ ] Injection
- [ ] Improper Assets Management
- [ ] Insufficient Logging & Monitoring

### Cloud/Infrastructure
- [ ] S3 bucket misconfiguration
- [ ] Azure blob exposure
- [ ] Cloud metadata SSRF (169.254.169.254)
- [ ] Subdomain takeover
- [ ] DNS misconfigurations
- [ ] Exposed admin panels
- [ ] Default cloud credentials

## Phase 3: Exploitation & PoC

### Best Practices for PoC
1. **Minimal impact** - Never access more data than needed to prove the issue
2. **Document everything** - Screenshots, HTTP requests/responses, timestamps
3. **Reproducible steps** - Clear 1-2-3 reproduction steps
4. **Show impact** - Demonstrate what an attacker could do
5. **Stay in scope** - Never test out-of-scope assets

### Impact Escalation
- Chain low-impact bugs for higher severity
- Open Redirect → OAuth token theft
- SSRF → Cloud metadata access → RCE
- XSS → Account takeover via session theft
- IDOR → Mass data exposure
- CSRF → State-changing actions on victim's behalf

## Phase 4: Reporting

### Report Structure
1. **Title** - Clear, concise, includes vulnerability type
2. **Severity** - CVSS score with justification
3. **Description** - What the vulnerability is
4. **Steps to Reproduce** - Detailed, numbered steps
5. **Proof of Concept** - Screenshots, code, HTTP requests
6. **Impact** - What an attacker can achieve
7. **Remediation** - How to fix it
8. **References** - CWE, OWASP, relevant advisories

### CVSS Severity Guidelines
- **Critical (9.0-10.0)**: RCE, authentication bypass, mass data breach
- **High (7.0-8.9)**: Stored XSS on sensitive pages, SQLi, SSRF to internal services
- **Medium (4.0-6.9)**: CSRF on sensitive actions, reflected XSS, IDOR with limited data
- **Low (0.1-3.9)**: Information disclosure, open redirect (standalone), minor misconfig

## Common Mistakes to Avoid
1. Not reading the program scope/policy
2. Testing on production with destructive payloads
3. Reporting missing best practices as vulnerabilities
4. Not providing adequate PoC
5. Over-claiming severity
6. Submitting duplicates without checking
7. Reporting self-XSS as a valid finding
8. Not chaining low-severity bugs
9. Ignoring out-of-scope notifications
10. Automated scanner results without manual validation
