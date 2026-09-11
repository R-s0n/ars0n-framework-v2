# Bug Bounty Report Writing Guide

## The Golden Rule
Your report is a sales pitch. You're selling the security team on why this vulnerability matters and why they should pay you for finding it.

## Report Structure

### Title
- Be specific and include the vulnerability type
- Bad: "XSS on website"
- Good: "Stored XSS via SVG upload in user profile avatar allows session hijacking"
- Include the affected endpoint or feature

### Severity Assessment
- Use CVSS 3.1 calculator for objective scoring
- Don't over-claim severity - this is the #1 reason for disputes
- Consider: Attack Complexity, Privileges Required, User Interaction, Scope, Confidentiality/Integrity/Availability Impact
- When in doubt, slightly under-claim - the triage team will bump it up if warranted

### Description
- Explain WHAT the vulnerability is in 2-3 sentences
- Reference the CWE if applicable
- Explain the root cause (not just the symptom)

### Steps to Reproduce
This is the MOST IMPORTANT section. If triage can't reproduce it, your report gets closed.

1. Number every step
2. Include exact URLs, parameters, and headers
3. Include screenshots at critical steps
4. Specify browser/tool versions if relevant
5. Note any prerequisites (account type, settings enabled, etc.)
6. Include raw HTTP requests/responses from Burp
7. Make it reproducible by someone who has never seen the app before

### Proof of Concept
- For XSS: Show `document.domain` or `document.cookie`, NOT `alert(1)`
- For SSRF: Show internal service response or cloud metadata
- For SQLi: Show database version or table names (NOT all data)
- For IDOR: Show access to another user's data (use your own test accounts)
- For RCE: Show `id` or `whoami`, NOT destructive commands
- NEVER: Access more data than needed, modify production data, or cause disruption

### Impact Statement
- Describe what an attacker could realistically achieve
- Quantify where possible: "affects all 50,000 users" vs "affects users"
- Chain with other findings if it amplifies impact
- Be honest - exaggeration destroys credibility

### Remediation
- Suggest specific fixes
- Reference OWASP or other standards
- Don't just say "sanitize input" - explain what kind of sanitization

## Common Mistakes That Get Reports Rejected

1. **No PoC or insufficient PoC** - Screenshots of scanner output are NOT a PoC
2. **Theoretical impact only** - "An attacker COULD..." without showing they CAN
3. **Scanner dumps** - Automated findings without manual verification
4. **Missing best practices ≠ vulnerability** - No HSTS header alone isn't a vuln
5. **Self-XSS** - If only the user can trigger it on themselves, it's not exploitable
6. **Out of scope** - Always check the program policy first
7. **Over-claiming severity** - A reflected XSS on a static page isn't Critical
8. **Duplicates** - Search Hacktivity/disclosed reports before submitting
9. **Poor communication** - Rude or demanding tones get reports deprioritized
10. **Not following program rules** - Some programs have specific reporting formats

## Severity Calibration

### Critical (typically $5,000-$50,000+)
- Remote Code Execution
- Authentication bypass (full)
- SQL injection with data exfiltration
- Account takeover (zero-click)
- Payment bypass with financial impact
- Mass PII exposure

### High (typically $2,000-$15,000)
- Stored XSS on authenticated pages
- SSRF to internal services
- Privilege escalation (user → admin)
- IDOR exposing sensitive user data
- JWT vulnerabilities leading to auth bypass

### Medium (typically $500-$5,000)
- Reflected XSS (authenticated context)
- CSRF on sensitive actions
- IDOR on non-sensitive data
- Information disclosure (internal IPs, versions)
- Rate limiting bypass on critical endpoints

### Low (typically $100-$1,000)
- Open redirect (standalone)
- Missing security headers (with demonstrated impact)
- CSRF on non-sensitive actions
- Information disclosure (minor)
- Clickjacking on non-sensitive pages

### Informational (typically $0)
- Missing best practices without exploitability
- Self-XSS
- Logout CSRF
- Content spoofing without impact
- Rate limiting missing (no demonstrated impact)

## Communication Tips
- Be professional and patient
- Respond to triage questions within 24-48 hours
- If your report is closed, politely explain why you disagree with evidence
- Don't spam comments asking for updates
- Thank the triage team - they're human too
- If severity is downgraded, accept it gracefully or provide additional evidence
