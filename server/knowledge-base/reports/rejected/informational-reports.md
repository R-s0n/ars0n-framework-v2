# Reports Downgraded to Informational

> Understanding why reports get closed as "Informative" on HackerOne (or P5/Informational on Bugcrowd) and how to avoid this outcome.

---

## What Does "Informational" Mean?

On HackerOne, reports closed as **"Informative"** contain useful information but do not warrant immediate action or a fix. On Bugcrowd, **P5 (Informational)** findings receive no financial or point-based rewards.

An informational closure means:
- The finding is acknowledged as technically accurate
- It does not meet the threshold for a security vulnerability
- No fix will be implemented
- No bounty or points are awarded (in most programs)
- It may negatively impact your Signal/reputation score

---

## Common Categories of Informational Findings

### 1. Subdomain Enumeration Without Takeover

**What was submitted:** A list of subdomains discovered through DNS enumeration, reported as "information disclosure."

**Why it was downgraded:** Subdomain discovery is reconnaissance, not a vulnerability. The subdomains exist and are resolvable by design.

**What the hunter should have done differently:**
- Use subdomain enumeration as a starting point for testing, not as a report
- Only report if a specific subdomain has a vulnerability (takeover, exposed admin panel, etc.)
- A subdomain list is your input to further testing, not your output

**Key lesson:** Reconnaissance findings are not vulnerabilities. They are the beginning of your research, not the end.

---

### 2. Directory Listing Enabled

**What was submitted:** A web server directory listing is enabled showing file names.

**Why it was downgraded:** The listed files do not contain sensitive information. Directory listing on a static assets folder or documentation directory is not a security issue.

**What the hunter should have done differently:**
- Check if the listed files contain sensitive data (credentials, source code, backups)
- Report the sensitive data exposure, not the directory listing itself
- If the directory only contains public CSS/JS/image files, do not report

**Key lesson:** Directory listing is informational unless it exposes sensitive files. The vulnerability is in what is exposed, not in the listing feature.

---

### 3. Verbose Error Messages (Without Sensitive Data)

**What was submitted:** Application returns detailed error messages including stack traces, framework information, or debug output.

**Why it was downgraded:** The error messages do not contain credentials, API keys, internal IPs, or other directly exploitable information.

**What the hunter should have done differently:**
- Look for actual sensitive data in the error output (database credentials, API keys, PII)
- Use the error information to find real vulnerabilities (exposed paths, SQL errors hinting at injection)
- Report the downstream vulnerability, not the error message itself

**Key lesson:** Stack traces and framework errors are informational. Credentials in error messages are a vulnerability.

---

### 4. Username/Email Enumeration (Context-Dependent)

**What was submitted:** Different responses for valid vs. invalid usernames on login, registration, or password reset pages.

**Why it was downgraded:** Many programs accept username enumeration as a known risk. For public-facing platforms (social media, SaaS with public profiles), usernames are inherently public.

**What the hunter should have done differently:**
- Check if the program's policy explicitly excludes username enumeration
- For platforms with public profiles, this is always informational
- Focus on enumeration that exposes email addresses on platforms where emails should be private
- Consider the context: a banking app may care, a social media app will not

**Key lesson:** Username enumeration is one of the most commonly downgraded findings. Only report it when the program specifically values email privacy and the enumeration exposes private information.

---

### 5. Autocomplete Enabled on Sensitive Fields

**What was submitted:** Password or credit card fields have `autocomplete` enabled.

**Why it was downgraded:** Browser autocomplete is a usability feature. Modern browsers handle credential storage securely. This is an extremely dated "vulnerability."

**What the hunter should have done differently:**
- Do not report this. It is universally considered informational.
- Focus on actual credential exposure or insecure storage issues

**Key lesson:** Autocomplete is not a vulnerability. This finding has not been accepted by serious programs for many years.

---

### 6. Software Version Disclosure

**What was submitted:** Server headers reveal Apache 2.4.51, PHP 8.1.2, or similar version information.

**Why it was downgraded:** Version information alone is informational. It does not directly lead to exploitation.

**What the hunter should have done differently:**
- Check if the version has known CVEs with public exploits
- If exploitable CVEs exist, exploit them and report the exploitation, not the version number
- Treat version information as input to your research

**Key lesson:** Report exploits, not version numbers. "This server runs version X" is never a bounty-worthy finding by itself.

---

### 7. Missing DNSSEC

**What was submitted:** The domain does not implement DNSSEC.

**Why it was downgraded:** DNSSEC adoption is a policy decision. Its absence is informational and does not create an exploitable vulnerability in the web application.

**What the hunter should have done differently:**
- Do not report missing DNSSEC unless the program specifically requests infrastructure assessments
- Focus on application-layer vulnerabilities

**Key lesson:** DNS security configuration is outside the scope of application bug bounties.

---

### 8. HTTP Methods Enabled (OPTIONS, TRACE)

**What was submitted:** The server responds to OPTIONS requests or has TRACE method enabled.

**Why it was downgraded:** OPTIONS is required for CORS preflight requests and is not a vulnerability. TRACE, while historically relevant (XST attacks), is mitigated by modern browsers blocking `XMLHttpRequest` TRACE requests.

**What the hunter should have done differently:**
- For TRACE, attempt an actual Cross-Site Tracing attack and demonstrate impact
- Understand that OPTIONS is a normal, expected HTTP method
- Do not report HTTP methods as vulnerabilities without exploitation

**Key lesson:** HTTP methods are not vulnerabilities. Only report if you can exploit them.

---

### 9. Exposed Non-Sensitive API Endpoints

**What was submitted:** An API endpoint is accessible without authentication but only returns public information.

**Why it was downgraded:** The endpoint is intentionally public. Public APIs returning public data are working as designed.

**What the hunter should have done differently:**
- Verify the data returned is actually sensitive or private
- Test for IDOR on endpoints that should return user-specific data
- Focus on endpoints returning private data without authorization

**Key lesson:** Public APIs returning public data are not vulnerabilities. The issue is when private data is exposed.

---

### 10. Path Disclosure

**What was submitted:** Error messages or responses reveal internal file paths (e.g., `/var/www/html/app/controllers/UserController.php`).

**Why it was downgraded:** Internal paths are informational. They may assist in further attacks but are not vulnerabilities themselves.

**What the hunter should have done differently:**
- Use path information to find more serious vulnerabilities (LFI, path traversal)
- Report the downstream vulnerability, not the path disclosure
- Combine with other findings if it enables a meaningful attack

**Key lesson:** Path disclosure is reconnaissance data, not a vulnerability.

---

## Patterns That Lead to Informational Ratings

| Pattern | Why It Is Informational | What Would Make It a Vulnerability |
|---------|------------------------|-----------------------------------|
| Information exists | By itself, information is not an exploit | When information enables a concrete attack |
| A feature works as designed | Design choices are not bugs | When the design creates an unintended security impact |
| A best practice is missing | Recommendations are not requirements | When the missing practice directly enables exploitation |
| Something is technically possible | Theoretical risk is not demonstrated risk | When you show actual exploitation and impact |

---

## How to Escalate Informational Findings to Real Vulnerabilities

1. **Chain findings together:** Self-XSS + CSRF = stored XSS (reportable)
2. **Demonstrate real impact:** Directory listing + sensitive file = data exposure
3. **Find the downstream vulnerability:** Version disclosure + CVE exploit = RCE
4. **Show business impact:** Username enumeration + credential stuffing = account takeover
5. **Increase the scope:** One IDOR instance may be informational, but systemic IDOR affecting all endpoints is critical

---

## Decision Tree: Is This Informational or a Vulnerability?

```
Does the finding allow an attacker to:
  |
  +-- Access data they should not see? --> VULNERABILITY (report it)
  |
  +-- Modify data they should not modify? --> VULNERABILITY (report it)
  |
  +-- Impersonate another user? --> VULNERABILITY (report it)
  |
  +-- Cause financial harm? --> VULNERABILITY (report it)
  |
  +-- Disrupt service availability? --> CHECK if DoS is in scope
  |
  +-- None of the above? --> Likely INFORMATIONAL (do not report)
```
