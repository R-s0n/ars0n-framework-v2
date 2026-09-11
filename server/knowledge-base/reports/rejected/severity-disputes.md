# Severity Disputes and Downgrades in Bug Bounty

> Understanding when and why severity is downgraded, how to set accurate severity, and how to handle disputes.
> Based on HackerOne CVSS guidelines, Bugcrowd VRT taxonomy, and community dispute patterns.

---

## Why Severity Disputes Happen

Severity disputes are the most contentious aspect of bug bounty. They occur because:

1. **Researchers lack full context** - They cannot see internal architecture, security controls, or data sensitivity
2. **Researchers overestimate impact** - Natural bias toward higher severity (higher reward)
3. **Programs underestimate impact** - Natural bias toward lower severity (lower cost)
4. **CVSS is context-dependent** - The same vulnerability type can be Critical or Low depending on the target
5. **Business impact vs. technical severity** - Programs weigh business impact, hunters focus on technical severity

---

## Most Common Severity Downgrade Scenarios

### 1. SSRF Downgraded from Critical/High to Medium/Low

**What was submitted (claimed Critical/High):** "I found SSRF that allows the application to make requests to internal services."

**Why it was downgraded:** The SSRF is limited in scope:
- Attacker does not control the full URL, only a path parameter
- Requests can only reach publicly accessible targets
- Internal metadata endpoints (169.254.169.254) are blocked
- Response is not returned to the attacker (blind SSRF)
- Protocol is restricted to HTTP/HTTPS only

**What the hunter should have done differently:**
- Test if cloud metadata endpoints are accessible (AWS/GCP/Azure)
- Determine if the response is returned (full vs. blind SSRF)
- Check if protocol smuggling is possible (file://, gopher://, dict://)
- Accurately describe limitations in the report
- Set severity based on what you CAN do, not what SSRF could theoretically do

**Key lesson:** SSRF severity ranges from P4 to P1 depending on what the attacker can reach and read. Blind SSRF with limited targets is not Critical.

---

### 2. XSS Downgraded from High to Medium/Low

**What was submitted (claimed High):** "Stored XSS on the application."

**Why it was downgraded:**
- The XSS is on a low-privilege page with no sensitive actions
- CSP significantly restricts what the XSS can do (no inline scripts, no eval)
- The XSS requires authentication and only affects users with a specific role
- The XSS is in a sandboxed iframe
- The affected page contains no sensitive data to steal

**What the hunter should have done differently:**
- Demonstrate actual impact: session hijacking, account takeover, data theft
- Show that CSP can be bypassed or does not prevent the attack
- Identify what an attacker gains from the XSS execution
- Set severity based on the actual demonstrated impact

**Key lesson:** XSS severity depends on what the attacker can accomplish, not just that JavaScript executes. XSS on a static marketing page is not the same as XSS on a banking dashboard.

---

### 3. IDOR Downgraded from High/Critical to Medium/Low

**What was submitted (claimed High):** "IDOR allows accessing other users' data."

**Why it was downgraded:**
- The data exposed is not sensitive (public profile information)
- The IDOR only allows reading, not modifying
- The object IDs are UUIDs that cannot be enumerated
- The accessed data is available through other legitimate means

**What the hunter should have done differently:**
- Demonstrate access to sensitive data (PII, financial data, private messages)
- Show if IDOR allows write/delete operations, not just read
- Demonstrate that object IDs can be enumerated or predicted
- Quantify the scope of data exposure

**Key lesson:** IDOR severity depends on the sensitivity of the exposed data and the operations possible (read vs. write vs. delete).

---

### 4. SQL Injection Downgraded from Critical to High/Medium

**What was submitted (claimed Critical):** "SQL injection on the application."

**Why it was downgraded:**
- The database user has minimal privileges (no FILE, no DBA)
- The injection is in an INSERT/UPDATE with limited data extraction
- The database contains no sensitive data (CMS content, not user credentials)
- WAF limits exploitation to basic data extraction (no RCE path)
- The injection is time-based blind only (limited data extraction speed)

**What the hunter should have done differently:**
- Extract actual sensitive data (credentials, PII, API keys)
- Test for privilege escalation within the database
- Check for file read/write capabilities
- Attempt OS command execution through the database
- Set severity based on demonstrated capabilities, not theoretical maximum

**Key lesson:** SQLi is not automatically Critical. The severity depends on what data the attacker can access and what privileges the database user has.

---

### 5. Information Disclosure Downgraded from Medium to Informational

**What was submitted (claimed Medium):** "The API exposes internal server information."

**Why it was downgraded:**
- The "internal information" is server version headers (publicly known)
- The disclosed information does not enable a specific attack
- The information is available through other means (Shodan, Censys)

**What the hunter should have done differently:**
- Only report information disclosure when the disclosed data is sensitive (credentials, PII, API keys)
- Show how the disclosed information enables a specific attack
- Report the attack enabled by the disclosure, not the disclosure itself

---

### 6. Open Redirect Downgraded from Medium to Low/Informational

**What was submitted (claimed Medium):** "Open redirect allows phishing attacks."

**Why it was downgraded:**
- The redirect is on a non-sensitive page
- The redirect cannot be chained with OAuth/SSO flows
- The URL is clearly visible to the user before redirection
- The program explicitly rates open redirects as Low/Informational

**What the hunter should have done differently:**
- Chain the redirect with OAuth to demonstrate token theft
- Show the redirect can bypass SSRF filters
- Check the program's policy on open redirect severity before reporting

---

### 7. Race Condition Downgraded from High to Medium/Low

**What was submitted (claimed High):** "Race condition on the coupon redemption endpoint."

**Why it was downgraded:**
- The race condition window is extremely small and unreliable
- The duplicate operation is detected and reversed by background processing
- The financial impact is negligible ($0.10 discount duplicated)

**What the hunter should have done differently:**
- Demonstrate reliable exploitation
- Show significant financial impact
- Verify that the duplicate operation persists (is not rolled back)

---

## How to Set Accurate Severity

### Use CVSS Honestly

When setting CVSS scores, be honest about:

| Factor | Common Overestimation | Accurate Assessment |
|--------|----------------------|---------------------|
| Attack Vector | Network | Is it really remotely exploitable without conditions? |
| Attack Complexity | Low | Are there prerequisites, conditions, or timing requirements? |
| Privileges Required | None | Does the attacker need an account? An admin account? |
| User Interaction | None | Does the victim need to click, visit, or perform an action? |
| Scope | Changed | Does the attack truly break out of the vulnerable component's scope? |
| Confidentiality | High | Is ALL data exposed, or just limited data? |
| Integrity | High | Can the attacker modify ALL data, or just specific fields? |
| Availability | High | Is the entire service disrupted, or just one feature? |

### Impact-Based Severity Guide

| Severity | Impact Description | Examples |
|----------|-------------------|----------|
| Critical (P1) | Full system compromise, mass data breach, unauthenticated RCE | RCE, auth bypass to admin, mass PII exposure |
| High (P2) | Significant data access or modification, privilege escalation | Account takeover, stored XSS on sensitive pages, SQLi with sensitive data |
| Medium (P3) | Limited data access, significant authenticated attacks | IDOR with moderate data, CSRF on sensitive actions, limited SSRF |
| Low (P4) | Minor impact, limited scope, requires significant conditions | Self-limited open redirects, minor info disclosure, rate limiting bypass |
| Informational (P5) | No direct security impact, best practices | Missing headers, version disclosure, non-sensitive configuration |

---

## How to Handle Severity Disputes

### Step 1: Understand the Program's Perspective
Programs see things you cannot: internal architecture, security controls, data sensitivity, and compensating controls. Their assessment may be more accurate than yours.

### Step 2: Provide Evidence, Not Arguments
If you believe severity should be higher:
- Demonstrate additional impact you did not include in the original report
- Show that compensating controls can be bypassed
- Provide real-world attack scenarios with concrete consequences
- Reference similar vulnerabilities on other programs for comparison

### Step 3: Use Platform Mediation
Major platforms offer mediation:
- **HackerOne:** Request mediation through the report
- **Bugcrowd:** Use the dispute resolution process
- **Intigriti:** Contact the platform for mediation

Mediators provide an independent assessment and are generally respected by both parties.

### Step 4: Accept the Outcome
If the severity is downgraded after review and mediation:
- Accept the decision gracefully
- Learn from the reasoning for future reports
- Do not argue indefinitely or become confrontational
- Reputation for professionalism matters for future private program invitations

---

## Common Severity Mistakes by Hunters

1. **Setting Critical for every SQL injection** - SQLi severity varies from P4 to P1
2. **Claiming RCE without demonstrating it** - "This could lead to RCE" is not RCE
3. **Using theoretical maximum impact** - "An attacker could potentially..." vs. "I demonstrated..."
4. **Ignoring compensating controls** - WAF, CSP, rate limiting, and monitoring all reduce severity
5. **Treating all data as sensitive** - Public profile data exposed via IDOR is not the same as financial records
6. **Confusing vulnerability type with severity** - The type does not determine severity; the impact does
7. **Not considering authentication requirements** - Pre-auth vs. post-auth vulnerabilities have very different severity

---

## Severity Assessment Checklist

Before setting severity, answer these questions:

- [ ] What can an attacker ACTUALLY do with this vulnerability (not theoretically)?
- [ ] What data can be accessed, and how sensitive is it?
- [ ] Does the attacker need authentication? What privilege level?
- [ ] Does the victim need to perform any action?
- [ ] Are there compensating controls that limit the impact?
- [ ] Is the exploitation reliable or dependent on timing/conditions?
- [ ] What is the realistic scope of impact (one user, many users, all users)?
- [ ] Have I demonstrated the maximum impact I am claiming?
