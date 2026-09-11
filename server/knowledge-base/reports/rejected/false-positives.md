# Common False Positive Findings in Bug Bounty

> Guide to recognizing and avoiding false positives that waste time and damage reputation.

---

## What Is a False Positive?

A false positive occurs when a security tool or manual test incorrectly identifies something as a vulnerability when it is not actually exploitable. Submitting false positives is one of the fastest ways to damage your reputation on bug bounty platforms.

---

## 1. Scanner-Reported XSS That Does Not Execute

**What was submitted:** Burp Suite or Nuclei reports reflected input in the response, but the payload does not actually execute JavaScript due to encoding, CSP, or context.

**Why it was rejected:** The scanner detected reflection but did not verify execution. The application properly encodes output or has a Content-Security-Policy that blocks inline scripts.

**What the hunter should have done differently:**
- Open the page in a browser and verify the JavaScript actually executes
- Check if CSP headers block inline script execution
- Verify the reflection context (inside an attribute, inside a script tag, inside HTML)
- Test with a simple `alert()` or `console.log()` and visually confirm

**Key lesson:** Reflected input does not equal XSS. Execution must be confirmed in an actual browser.

---

## 2. SQL Injection False Positives from Time-Based Detection

**What was submitted:** SQLMap or manual testing reported a time-based blind SQL injection, but the delay was caused by network latency, server load, or application logic rather than actual injection.

**Why it was rejected:** The time delay was inconsistent and not caused by SQL execution. The application was not actually vulnerable.

**What the hunter should have done differently:**
- Test multiple times to confirm consistent delay differences
- Use mathematical verification (5-second delay vs 10-second delay should show proportional difference)
- Try to extract actual data (database version, table names) to confirm
- Rule out network jitter and server-side rate limiting as causes of delays
- Use both true and false conditions to verify boolean-based behavior

**Key lesson:** Time-based SQLi has the highest false positive rate of any injection technique. Always verify with data extraction or boolean confirmation.

---

## 3. CORS Misconfiguration Without Credentialed Access

**What was submitted:** The server reflects the Origin header in Access-Control-Allow-Origin, reported as a CORS misconfiguration.

**Why it was rejected:** The server does not include `Access-Control-Allow-Credentials: true`, meaning cookies are not sent cross-origin. Without credentials, the attacker cannot access authenticated data.

**What the hunter should have done differently:**
- Verify that `Access-Control-Allow-Credentials: true` is present
- Confirm that the reflected origin actually allows reading sensitive data
- Build a proof of concept that demonstrates cross-origin data theft
- Check if the endpoint returns any sensitive/authenticated data at all

**Key lesson:** CORS reflection without credentials is typically not exploitable. The full CORS configuration must be evaluated, not just one header.

---

## 4. Open Redirect on Non-Sensitive Endpoints

**What was submitted:** An open redirect on a marketing page, documentation site, or other non-authenticated endpoint.

**Why it was rejected:** The redirect does not lead to credential theft, session hijacking, or any meaningful security impact. Many programs explicitly exclude open redirects unless chained with another vulnerability.

**What the hunter should have done differently:**
- Check if the program accepts open redirects at all
- Attempt to chain with OAuth/SSO flows to steal tokens
- Demonstrate phishing potential with realistic attack scenario
- Consider if the redirect can bypass SSRF filters

**Key lesson:** Open redirects alone are rarely accepted. They must be chained with another vulnerability or shown to have concrete impact on authentication flows.

---

## 5. Missing Security Headers on Non-Sensitive Pages

**What was submitted:** Missing X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, or Content-Security-Policy headers.

**Why it was rejected:** Missing headers without a demonstrated exploit are best practice violations, not vulnerabilities. Almost every program excludes these.

**What the hunter should have done differently:**
- Only report if you can demonstrate an actual exploit enabled by the missing header
- For missing X-Frame-Options, demonstrate a working clickjacking attack on a page with sensitive actions
- For missing CSP, demonstrate an actual XSS that CSP would have prevented

**Key lesson:** Missing headers are not vulnerabilities by themselves. They must enable a concrete, demonstrable attack.

---

## 6. Subdomain Takeover False Positives

**What was submitted:** A dangling CNAME record pointing to a cloud service, reported as a subdomain takeover.

**Why it was rejected:** The CNAME points to a service that does not allow claiming arbitrary subdomains (e.g., many AWS services, Cloudflare), or the service still has an active configuration even though it returns a 404.

**What the hunter should have done differently:**
- Verify the service actually allows subdomain claiming (check can-i-take-over-xyz lists)
- Actually attempt the takeover in a safe manner and provide proof
- Distinguish between "returns an error page" and "is actually claimable"
- Check if the DNS record is a wildcard that catches everything

**Key lesson:** A dangling CNAME is not automatically a takeover. You must verify the specific service allows claiming and ideally demonstrate the takeover.

---

## 7. SSRF That Only Reaches Internal Metadata (But Cannot)

**What was submitted:** A parameter that accepts URLs, reported as SSRF.

**Why it was rejected:** The application validates URLs, blocks internal addresses, or uses a proxy that prevents reaching internal services. The hunter did not actually access any internal resource.

**What the hunter should have done differently:**
- Actually demonstrate access to internal resources (169.254.169.254, internal services)
- Try bypass techniques if basic attempts are blocked
- Show the response from an internal service, not just that a URL parameter exists
- Verify the request is made server-side, not client-side (which would be just an open redirect)

**Key lesson:** A URL input field is not SSRF. You must demonstrate server-side requests reaching internal resources.

---

## 8. Information Disclosure That Is Not Sensitive

**What was submitted:** Server version headers, technology stack information, or framework version numbers.

**Why it was rejected:** Version disclosure alone is informational. Unless the disclosed version has a known, exploitable CVE in the target's context, this is not a vulnerability.

**What the hunter should have done differently:**
- Check if the disclosed version has known CVEs
- If it does, attempt to exploit the CVE and report that instead
- Understand that most programs explicitly exclude version/technology disclosure

**Key lesson:** Knowing that a server runs Apache 2.4.52 is useless without a working exploit for that version. Report the exploit, not the version number.

---

## 9. CSRF on Non-State-Changing or Non-Sensitive Actions

**What was submitted:** CSRF on login forms, logout endpoints, search queries, language preference changes, or newsletter subscriptions.

**Why it was rejected:** The action has no meaningful security impact. Forcing a user to log out or change their language preference does not compromise their security.

**What the hunter should have done differently:**
- Only report CSRF on state-changing actions with real impact (password change, email change, financial transactions)
- Consider if login CSRF can be chained to fix a victim's session to an attacker-controlled account
- Verify the action actually changes something sensitive in the user's account

**Key lesson:** CSRF impact depends entirely on what action is being forged. Login/logout CSRF is almost universally excluded.

---

## 10. Clickjacking on Pages Without Sensitive Actions

**What was submitted:** A page can be iframed (missing X-Frame-Options), reported as clickjacking.

**Why it was rejected:** The page that can be iframed does not contain any sensitive actions (buttons, forms) that an attacker could trick a user into clicking.

**What the hunter should have done differently:**
- Identify a page with a sensitive action (delete account, transfer funds, change settings)
- Build a working clickjacking PoC that demonstrates the attack
- Show that one or two clicks in the iframe trigger a harmful action

**Key lesson:** Clickjacking requires both the ability to iframe AND a sensitive action on the framed page. Without both, there is no vulnerability.

---

## 11. Race Conditions Without Impact

**What was submitted:** A TOCTOU (time-of-check-to-time-of-use) race condition on a non-sensitive endpoint.

**Why it was rejected:** The race condition does not lead to any meaningful outcome like duplicate payments, extra credits, or privilege escalation.

**What the hunter should have done differently:**
- Focus on race conditions that affect financial transactions, coupon redemption, or resource allocation
- Demonstrate the actual impact of winning the race
- Show that the race condition can be reliably triggered

**Key lesson:** Race conditions are only valuable when winning the race produces a meaningful security or business impact.

---

## 12. Email-Related "Vulnerabilities"

**What was submitted:** Ability to send emails through the application's contact form, password reset, or notification system, reported as "email spoofing" or "email bombing."

**Why it was rejected:** The application's email-sending functionality is working as designed. Sending password reset emails is not a vulnerability.

**What the hunter should have done differently:**
- Check if you can modify the sender address (FROM header) to impersonate others
- Verify if there is actual email injection allowing arbitrary headers
- Look for SMTP injection, not just the ability to trigger legitimate emails

**Key lesson:** Triggering an application to send its own legitimate emails is not a vulnerability. Email injection requires modifying headers or recipients.

---

## False Positive Checklist

Before submitting any finding, verify:

- [ ] The vulnerability executes/triggers in an actual browser or client (not just in tool output)
- [ ] The finding is not caused by a browser extension, proxy, or local configuration
- [ ] The same result occurs in a clean browser environment
- [ ] The impact is real and not theoretical
- [ ] You have attempted actual exploitation, not just detection
- [ ] The finding survives encoding, filtering, and security controls
- [ ] Network-related findings account for latency and server load variations
