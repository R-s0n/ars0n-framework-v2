# Common Duplicate Patterns and How to Avoid Them

> Understanding why duplicates happen and strategies to find unique vulnerabilities.
> Based on research from Bugcrowd, HackerOne, NahamSec, and community experience.

---

## Understanding Duplicates

A duplicate is a report for a vulnerability that has already been reported by another researcher. Duplicates are the most frustrating outcome for hunters because:

- The finding is valid, but you receive no reward
- Your time investment is completely lost
- On some platforms, excessive duplicates affect reputation
- It indicates you are competing in the same space as many other hunters

---

## The Three Principles of Duplicates (Bugcrowd Framework)

### Principle 1: Touch the Code
If a finding causes the program to make a code change, it should be rewarded. If a fix for one report also fixes your report, yours is a duplicate.

### Principle 2: Same Root Cause
Two findings with the same root cause are duplicates even if they manifest on different endpoints. Example: If missing authorization on `/api/users/1` is the same code path as `/api/users/2`, only the first report is unique.

### Principle 3: Systemic vs. Instance
When an issue is systemic (same flaw across many endpoints), the first report is rewarded and all subsequent reports are duplicates. However, if two fixes must be applied independently (different code paths), each is a unique finding.

---

## Most Commonly Duplicated Vulnerability Types

### 1. Subdomain Takeover

**Why it is duplicated:** Automated tools like Subjack, Nuclei, and SubOver scan for dangling CNAMEs. Hundreds of hunters run these tools on the same targets daily.

**Duplicate rate:** Extremely high. Subdomain takeovers found by automated scanning are almost always already reported.

**How to avoid:**
- Focus on non-standard services not covered by automated tools
- Look for second-order subdomain takeovers (subdomains of subdomains)
- Monitor for newly created/deleted DNS records rather than scanning existing ones
- Check services not in the standard takeover fingerprint databases

---

### 2. Open Redirect

**Why it is duplicated:** Open redirect scanners are built into most recon frameworks. The same redirect parameters (`?url=`, `?redirect=`, `?next=`, `?return=`) are tested by every hunter.

**Duplicate rate:** Very high, especially on well-known parameters.

**How to avoid:**
- Look for open redirects in non-obvious places (JavaScript-based, meta refresh, header injection)
- Chain open redirects with OAuth flows to steal tokens (increases value and uniqueness)
- Focus on redirects that bypass validation through encoding tricks

---

### 3. Missing Rate Limiting

**Why it is duplicated:** Every hunter tests login and password reset endpoints for rate limiting. It is one of the first things beginners look for.

**Duplicate rate:** Very high on major programs.

**How to avoid:**
- Look for rate limiting bypasses rather than missing rate limiting
- Test less obvious endpoints (OTP verification, API key generation, invitation systems)
- Focus on rate limiting issues with higher impact (financial transactions, SMS sending)

---

### 4. IDOR (Insecure Direct Object Reference)

**Why it is duplicated:** IDOR on obvious endpoints (user profiles, orders, invoices) is heavily hunted. The most visible IDOR instances are found quickly.

**Duplicate rate:** High on obvious endpoints, low on deep functionality.

**How to avoid:**
- Go deeper into the application - test admin functions, reporting features, export functions
- Look for IDOR in API endpoints that are not directly linked from the UI
- Test GraphQL queries and mutations for authorization issues
- Focus on IDOR in file access, not just data access

---

### 5. Information Disclosure via Common Paths

**Why it is duplicated:** Tools scan for `.env`, `.git`, `phpinfo.php`, `server-status`, `/debug`, and similar paths. Every scanner includes these checks.

**Duplicate rate:** Extremely high. If a common path scanner finds it, it has been reported.

**How to avoid:**
- Look for application-specific information disclosure (custom debug endpoints, backup files with timestamps)
- Focus on information in API responses rather than common file paths
- Check for information leakage in mobile API endpoints

---

### 6. XSS on Common Parameters

**Why it is duplicated:** Reflected XSS on search fields, error messages, and URL parameters is heavily automated. Tools like XSSHunter, Dalfox, and kxss find these quickly.

**Duplicate rate:** Very high on surface-level XSS.

**How to avoid:**
- Look for DOM-based XSS that requires JavaScript analysis
- Focus on Stored XSS in less-tested features (admin panels, reporting dashboards)
- Find XSS in PDF generators, email templates, or export functions
- Test for XSS in WebSocket messages, postMessage handlers, or service workers

---

### 7. CORS Misconfiguration

**Why it is duplicated:** CORS testing is automated and every scanner checks for it. Origin reflection and wildcard CORS are the first things tested.

**Duplicate rate:** High on obvious misconfigurations.

**How to avoid:**
- Look for CORS misconfigurations on specific subdomains, not just the main domain
- Test pre-production environments if in scope
- Focus on CORS combined with credentials on sensitive endpoints

---

## Strategies to Avoid Duplicates

### Strategy 1: Hunt on New Programs
- **Join platforms early** and hunt on newly launched programs
- Programs receive the fewest reports in their first 2 weeks
- Set up notifications for new program launches on HackerOne, Bugcrowd, and Intigriti

### Strategy 2: Hunt on Updated Assets
- Monitor for new features, redesigns, and newly deployed subdomains
- New code has new bugs - test changes, not legacy functionality
- Use tools like Wayback Machine diffing to spot new endpoints

### Strategy 3: Go Deep, Not Wide
- Spend days understanding one application instead of hours scanning hundreds
- Map business logic, user roles, and data flows
- Find bugs that require understanding the application's purpose
- Business logic bugs are almost never duplicated

### Strategy 4: Develop Unique Methodology
- Build custom tools for specific vulnerability classes
- Develop expertise in uncommon vulnerability types (deserialization, race conditions, SSRF chains)
- Focus on areas that automated tools cannot test (multi-step workflows, stateful attacks)

### Strategy 5: Focus on High-Severity Findings
- Critical and high-severity bugs have lower duplicate rates than low/medium
- One critical finding is worth more than ten low-severity ones
- The effort to find a critical bug discourages casual hunters

### Strategy 6: Test Less Popular Assets
- If a program lists 50 domains, most hunters test the main domain
- Test secondary domains, mobile APIs, internal tools, and partner integrations
- Less popular assets receive fewer reports

### Strategy 7: Monitor Continuously
- Set up continuous monitoring for DNS changes, new subdomains, new JavaScript files
- Be the first to test newly deployed code
- Automate reconnaissance and check results daily

---

## Understanding the Duplicate Lifecycle

```
Time After Program Launch:
  |
  Day 1-3:   Low-hanging fruit reported (subdomain takeover, obvious XSS, common files)
  Day 4-14:  Medium-depth findings reported (IDOR, CORS, API issues)
  Day 15-60: Deep findings reported (business logic, complex chains, race conditions)
  Day 60+:   Only novel findings avoid duplicates
```

**Implication:** If you start hunting on a program after 60 days, only deep, novel, or newly introduced bugs will avoid duplicate status.

---

## When a Finding Is NOT a Duplicate

Despite appearing similar, these are separate findings:

1. **Same vulnerability type, different root cause:** IDOR on `/api/v1/users` (missing auth middleware) vs. IDOR on `/api/v2/users` (broken parameter validation) -- different code fixes required
2. **Same endpoint, different parameter:** SQLi in `?search=` vs. SQLi in `?sort=` on the same endpoint -- different input handling
3. **Same vulnerability, different subdomain:** XSS on `app.company.com` vs. XSS on `admin.company.com` -- different applications
4. **Same type, different impact:** Open redirect on marketing site vs. open redirect in OAuth callback -- fundamentally different impact

---

## What to Do When You Get a Duplicate

1. **Do not argue aggressively** - Respect the triager's decision
2. **Ask for clarification** - "Was this reported on the same endpoint or is it a systemic issue?"
3. **Request mediation** - If you believe the decision is wrong, use the platform's mediation process
4. **Learn from it** - Analyze why you were too late and adjust your strategy
5. **Move on** - Time spent arguing about duplicates is time not spent finding new bugs
