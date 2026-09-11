# Best Practice Violations vs. Actual Vulnerabilities

> Understanding the critical difference between "this could be better" and "this can be exploited."
> Reports about missing best practices are the hallmark of "beg bounties" and damage hunter reputation.

---

## The Core Distinction

**Best Practice Violation:** A configuration or implementation that does not follow industry recommendations but does not create an exploitable vulnerability.

**Actual Vulnerability:** A flaw that allows an attacker to compromise confidentiality, integrity, or availability of the system or its users.

**The Test:** Can you demonstrate a concrete attack that harms a user or the organization? If not, it is a best practice violation.

---

## Category 1: Missing HTTP Security Headers

### Missing Content-Security-Policy (CSP)

**Best practice violation:** "The application does not implement CSP headers."

**Actual vulnerability:** "The application has a Stored XSS vulnerability in the comment field. While CSP could mitigate this, the absence of CSP is not the vulnerability -- the XSS is."

**Rule:** Report the XSS, not the missing CSP. CSP is a defense-in-depth control.

---

### Missing X-Frame-Options / frame-ancestors

**Best practice violation:** "The login page can be iframed."

**Actual vulnerability:** "The account settings page (which allows email/password changes) can be iframed, and I have built a working clickjacking PoC that tricks users into changing their email address."

**Rule:** Clickjacking requires both framability AND a sensitive action. Report the attack, not the missing header.

---

### Missing Strict-Transport-Security (HSTS)

**Best practice violation:** "The application does not send HSTS headers."

**Actual vulnerability:** "The application does not redirect HTTP to HTTPS, and session cookies lack the Secure flag, allowing session hijacking on public WiFi."

**Rule:** HSTS alone is informational. The ability to intercept sensitive data over HTTP is the vulnerability.

---

### Missing X-Content-Type-Options

**Best practice violation:** "The application does not send X-Content-Type-Options: nosniff."

**Actual vulnerability:** This header prevents MIME-type sniffing. In modern browsers, the attack scenarios this prevents are largely mitigated. This finding is almost never a vulnerability.

**Rule:** Do not report missing X-Content-Type-Options. It is universally considered informational.

---

### Missing Referrer-Policy

**Best practice violation:** "The application does not set a Referrer-Policy header."

**Actual vulnerability:** "Password reset tokens are included in URLs, and the reset page loads external resources. The Referrer header leaks the token to third-party analytics services."

**Rule:** Missing Referrer-Policy is informational. Token leakage via Referer to external services is a vulnerability.

---

## Category 2: Email Security Configuration

### Missing or Weak DMARC Policy

**Best practice violation:** "The domain has DMARC set to p=none" or "No DMARC record exists."

**Actual vulnerability:** Almost never a valid bug bounty finding. Email authentication is an infrastructure policy decision.

**What hunters actually do:** Mass-submit DMARC findings to every program. This is the textbook "beg bounty" behavior.

**Rule:** Do not report missing DMARC/SPF/DKIM unless the program explicitly includes email infrastructure in scope.

---

### Missing SPF Record

**Best practice violation:** "No SPF record exists for the domain."

**Why it is not a vulnerability for bug bounty:** SPF is one component of email authentication. Its absence does not mean emails can be spoofed successfully (DMARC and DKIM also play roles, and recipient mail servers have their own filtering).

**Rule:** Same as DMARC. This is infrastructure configuration, not an application vulnerability.

---

## Category 3: Cookie Configuration

### Missing Secure Flag on Cookies

**Best practice violation:** "Session cookies do not have the Secure flag."

**Actual vulnerability:** "Session cookies without the Secure flag are transmitted over HTTP on a site that does not enforce HTTPS, allowing session hijacking via network sniffing. Here is a working PoC using a MitM proxy."

**Rule:** Missing Secure flag is informational IF the site enforces HTTPS everywhere. It becomes a vulnerability only when combined with HTTP access.

---

### Missing HttpOnly Flag on Session Cookies

**Best practice violation:** "Session cookies do not have the HttpOnly flag."

**Actual vulnerability:** "There is an XSS vulnerability at /endpoint, and because session cookies lack HttpOnly, I can steal session tokens via document.cookie."

**Rule:** Missing HttpOnly is informational without XSS. Report the XSS; mention the missing HttpOnly as an aggravating factor.

---

### Missing SameSite Attribute

**Best practice violation:** "Cookies do not set SameSite=Strict or SameSite=Lax."

**Actual vulnerability:** "A CSRF vulnerability exists on /transfer endpoint because cookies default to SameSite=None with Secure, allowing cross-origin requests to carry authentication cookies."

**Rule:** Modern browsers default to SameSite=Lax. Missing SameSite attribute alone is not a vulnerability.

---

## Category 4: Authentication Configuration

### Password Policy Issues

**Best practice violation:** "The application allows passwords shorter than 12 characters" or "No complexity requirements."

**Why it is not a vulnerability:** Password policy is a business decision balancing security and usability. Weak passwords are the user's choice.

**Rule:** Do not report password policy as a vulnerability. It is universally considered a design decision.

---

### Missing Multi-Factor Authentication

**Best practice violation:** "The application does not support or enforce MFA."

**Why it is not a vulnerability:** MFA is a security feature, not a vulnerability fix. Its absence is a product decision.

**Rule:** Never report missing MFA as a bug bounty finding.

---

### Missing Account Lockout

**Best practice violation:** "The application does not lock accounts after failed login attempts."

**Actual vulnerability:** "The login endpoint has no rate limiting AND no account lockout, allowing brute-force attacks. I successfully guessed a test account's password in X attempts."

**Rule:** Missing lockout alone is informational. Combined with no rate limiting and demonstrated brute force, it can be valid.

---

### Session Does Not Expire

**Best practice violation:** "Sessions remain valid indefinitely."

**Actual vulnerability:** Long session lifetimes increase the window for session hijacking but are not vulnerabilities by themselves.

**Rule:** Session timeout is a design decision. Only report if combined with another vulnerability.

---

## Category 5: Information Exposure

### Technology Stack Disclosure

**Best practice violation:** "The Server header reveals Apache/2.4.52. The X-Powered-By header reveals PHP/8.1."

**Why it is not a vulnerability:** This information helps attackers but does not enable an attack by itself. The vast majority of programs exclude this.

**Rule:** Suppress the urge to report version headers. Use the information to find real vulnerabilities.

---

### Robots.txt / Sitemap.xml Exposure

**Best practice violation:** "The robots.txt file reveals internal paths."

**Why it is not a vulnerability:** robots.txt is a public file. It tells search engines what not to index, but it is accessible to everyone. Listing paths in robots.txt is not information disclosure.

**Rule:** Use robots.txt as reconnaissance input. Do not report its existence.

---

### Publicly Accessible .well-known Endpoints

**Best practice violation:** "/.well-known/security.txt is accessible" or "/.well-known/openid-configuration is accessible."

**Why it is not a vulnerability:** These endpoints are designed to be public. security.txt is literally an invitation to report bugs.

**Rule:** Never report public-by-design endpoints as information disclosure.

---

## Category 6: Rate Limiting and Abuse Prevention

### Missing Rate Limiting on Non-Sensitive Endpoints

**Best practice violation:** "The /search endpoint has no rate limiting."

**Why it is not a vulnerability:** Search endpoints, public API endpoints, and content listing endpoints are designed to handle many requests. Missing rate limiting on these is an operational concern, not a security vulnerability.

**Rule:** Only report missing rate limiting on authentication (login, OTP verification), password reset, and financial transaction endpoints.

---

### Missing CAPTCHA

**Best practice violation:** "The registration form has no CAPTCHA."

**Why it is not a vulnerability:** CAPTCHA is an anti-abuse measure. Its absence enables spam, not security compromise.

**Rule:** Do not report missing CAPTCHA as a security vulnerability.

---

## The "Beg Bounty" Checklist

If your report matches ANY of the following patterns, it is likely a beg bounty. Do NOT submit:

- [ ] Missing [any security header] without a working exploit
- [ ] Missing DMARC/SPF/DKIM records
- [ ] Missing rate limiting on non-critical endpoints
- [ ] Missing CAPTCHA
- [ ] Missing MFA
- [ ] Password policy complaints
- [ ] Version/technology disclosure
- [ ] Cookie flags without corresponding exploitation
- [ ] Session timeout configuration
- [ ] robots.txt content
- [ ] Public .well-known endpoints
- [ ] HTML lacks autocomplete="off"
- [ ] Missing Subresource Integrity (SRI) on third-party scripts (without demonstrating tampering)

---

## When Best Practice Violations BECOME Vulnerabilities

The transformation happens through **chaining** and **demonstrated impact**:

| Best Practice Violation | + Chain With | = Vulnerability |
|------------------------|-------------|-----------------|
| Missing CSP | + Working XSS | Aggravated XSS (mention CSP absence in impact) |
| Missing X-Frame-Options | + Sensitive action on frameable page | Clickjacking with PoC |
| Missing Secure flag | + HTTP endpoint serving the page | Session hijacking via MitM |
| Missing HttpOnly | + Working XSS | Cookie theft via XSS |
| Missing rate limiting | + Login/OTP endpoint | Brute force attack |
| Missing SameSite | + CSRF-able state-changing endpoint | CSRF with working PoC |
| Missing HSTS | + SSLStrip attack | Credential interception |

**The rule is simple: Report the exploit, not the missing control.**
