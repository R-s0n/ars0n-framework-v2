# Typical Out-of-Scope Findings in Bug Bounty Programs

> Comprehensive list of vulnerability types and assets commonly excluded from bug bounty programs.

---

## Why Out-of-Scope Matters

Submitting out-of-scope findings wastes your time, the triager's time, and damages your reputation score. Most platforms penalize hunters for out-of-scope submissions. Always read the program policy completely before testing.

---

## Commonly Excluded Vulnerability Types

### 1. Missing Security Headers

**Typically excluded:**
- Missing Strict-Transport-Security (HSTS)
- Missing X-Frame-Options (without demonstrable clickjacking)
- Missing X-Content-Type-Options
- Missing X-XSS-Protection (deprecated header)
- Missing Content-Security-Policy
- Missing Referrer-Policy
- Missing Permissions-Policy

**Why excluded:** These are defense-in-depth measures. Their absence alone does not create an exploitable vulnerability.

**When it IS in scope:** If you can demonstrate a concrete attack that the missing header would have prevented (e.g., working clickjacking PoC on a sensitive page due to missing X-Frame-Options).

---

### 2. Missing Email Security Records

**Typically excluded:**
- Missing or misconfigured SPF records
- Missing or misconfigured DKIM records
- Missing or misconfigured DMARC records
- DMARC policy set to "none" instead of "reject"

**Why excluded:** These are email authentication best practices. Their absence is an infrastructure configuration issue, not an application vulnerability. Programs consider these "beg bounties."

**When it IS in scope:** Rarely, but some programs accept email spoofing demonstrations where missing DMARC allows sending convincing phishing emails from the organization's domain.

---

### 3. SSL/TLS Configuration Issues

**Typically excluded:**
- Support for older TLS versions (TLS 1.0, 1.1)
- Weak cipher suites (unless actively broken like RC4)
- Certificate transparency issues
- BEAST, POODLE, and similar legacy attacks
- Missing HSTS preload
- Certificate expiration warnings (not expired)

**Why excluded:** Most of these are theoretical or require MitM position. Modern browsers handle cipher negotiation safely regardless of server configuration.

**When it IS in scope:** Active use of broken cryptography where data can actually be decrypted, or certificate issues on API endpoints handling sensitive data.

---

### 4. Denial of Service (DoS/DDoS)

**Typically excluded:**
- Volumetric DDoS attacks
- Resource exhaustion through excessive requests
- Application-level DoS through normal functionality
- Regex DoS (ReDoS) without significant impact
- Zip bombs or XML bombs (unless processing is confirmed)
- Slowloris and similar connection-exhaustion attacks

**Why excluded:** Programs do not want researchers disrupting their services. DoS is often trivially achievable and not a design flaw.

**When it IS in scope:** Some programs accept application-level DoS that crashes the server with a single request, asymmetric resource consumption bugs, or ReDoS on critical processing paths.

---

### 5. Social Engineering

**Typically excluded:**
- Phishing attacks against employees
- Vishing (voice phishing)
- Physical social engineering
- Pretexting
- Baiting

**Why excluded:** These are human-factor attacks, not technical vulnerabilities. Programs test technical security, not employee training.

**When it IS in scope:** Almost never, unless the program explicitly includes social engineering (extremely rare).

---

### 6. Physical Attacks

**Typically excluded:**
- Physical access attacks
- USB drop attacks
- Hardware tampering
- Dumpster diving

**Why excluded:** Bug bounty programs focus on remote, technical vulnerabilities.

---

### 7. Self-XSS

**Typically excluded:**
- XSS that only affects the attacker's own session
- XSS requiring the victim to paste code into their browser console
- XSS in user-controlled fields visible only to that user (without stored XSS to others)

**Why excluded:** There is no victim other than the attacker themselves. See `self-xss.md` for detailed coverage.

---

### 8. Login/Logout CSRF

**Typically excluded:**
- CSRF on login forms
- CSRF on logout endpoints
- CSRF on non-sensitive forms (search, language, preferences)

**Why excluded:** Forcing a user to log in or log out has no meaningful security impact in most contexts.

**When it IS in scope:** Login CSRF that fixes a victim's session to an attacker-controlled account (enabling session fixation).

---

### 9. Rate Limiting Issues (Context-Dependent)

**Typically excluded:**
- Missing rate limiting on non-sensitive endpoints
- Missing rate limiting on public APIs
- Missing rate limiting on search functionality
- Ability to send multiple password reset emails

**Why excluded:** Rate limiting is an operational control. Its absence on non-critical endpoints is not a security vulnerability.

**When it IS in scope:** Missing rate limiting on authentication endpoints enabling brute force, missing rate limiting on OTP verification enabling bypass, or missing rate limiting on financial operations.

---

### 10. Content Injection Without XSS

**Typically excluded:**
- HTML injection that does not execute JavaScript
- Injecting formatted text into pages
- Content spoofing on non-sensitive pages

**Why excluded:** Without JavaScript execution, the security impact is minimal. Content injection is cosmetic.

**When it IS in scope:** Content injection on login pages that could enable realistic phishing.

---

### 11. Version/Technology Disclosure

**Typically excluded:**
- Server version headers (Apache, Nginx, IIS version)
- Framework version disclosure (Rails, Django, Spring version)
- Programming language disclosure
- CMS version disclosure
- Stack traces and error messages (without sensitive data)

**Why excluded:** Technology information does not directly lead to exploitation. Programs focus on exploitable vulnerabilities, not reconnaissance findings.

**When it IS in scope:** Verbose error messages exposing database credentials, API keys, internal paths with sensitive information, or source code.

---

### 12. Cookie Configuration Issues

**Typically excluded:**
- Missing Secure flag on non-sensitive cookies
- Missing HttpOnly flag (without demonstrated XSS to exploit it)
- Missing SameSite attribute
- Overly broad cookie scope (without exploitation)

**Why excluded:** Cookie flag issues are best practices. Without a corresponding attack that exploits the missing flag, there is no vulnerability.

---

### 13. Brute Force Attacks

**Typically excluded:**
- Credential brute forcing
- API key brute forcing
- Token brute forcing (unless feasible)

**Why excluded:** Programs do not want active brute force against their systems. This overlaps with DoS concerns.

**When it IS in scope:** If you can demonstrate that a token/session has insufficient entropy making brute force feasible (e.g., a 4-digit OTP with no rate limiting).

---

## Commonly Excluded Assets

### Typically Out of Scope:
- Third-party services and integrations (Zendesk, Intercom, Google Analytics)
- Staging/development environments (unless explicitly listed)
- Email systems (mail.company.com)
- Corporate infrastructure vs. product infrastructure
- Blog platforms (blog.company.com on WordPress)
- Status pages (status.company.com)
- Marketing sites vs. application
- DNS infrastructure
- CDN-related issues (Cloudflare, Akamai misconfigurations)

---

## How to Verify Scope Before Testing

1. **Read the full program policy** including all exclusions
2. **Check the asset list** for explicit domain/IP listings
3. **Look for wildcard scope** (*.company.com) vs. specific subdomains
4. **Check the vulnerability exclusions** section
5. **Look for safe harbor provisions** that define what testing is allowed
6. **When in doubt, ask** - most platforms allow pre-submission questions to the program

---

## Common Mistakes with Scope

| Mistake | Example | Result |
|---------|---------|--------|
| Testing out-of-scope domains | Testing staging.company.com when only app.company.com is listed | Rejection |
| Reporting excluded vuln types | Submitting missing CSP header | Rejection + reputation hit |
| Assuming wildcard means everything | *.company.com does not include third-party hosted services | Rejection |
| Not checking for updated scope | Program removed an asset but hunter tests old scope | Rejection |
| Testing acquisitions | New acquisition domain not yet added to scope | Rejection |
