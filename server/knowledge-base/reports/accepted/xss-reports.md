# XSS (Cross-Site Scripting) Bug Bounty Reports

> A collection of accepted/disclosed XSS vulnerability reports from bug bounty programs. Organized by XSS type (Stored, Reflected, DOM-based).

---

## Stored XSS Reports

### 1. Stored XSS via SVG File on Shopify
- **Severity:** High
- **Vulnerability Type:** Stored XSS
- **Platform:** HackerOne
- **Program:** Shopify
- **Bounty:** $5,300
- **Description:** A stored XSS vulnerability was found where an attacker could upload an SVG file containing malicious JavaScript as a data: URL. When other users viewed the content, the script executed in their browser context.
- **How It Was Found:** Manual testing of file upload functionality, specifically testing SVG files with embedded JavaScript payloads.
- **Impact:** Session hijacking, account takeover, data theft from authenticated Shopify admin users.
- **Key Takeaway:** Always test file upload features with SVG files containing JavaScript. Many applications fail to sanitize SVG content properly.
- **Source:** https://hackerone.com/reports/391390

### 2. Stored XSS in Shopify Admin Product Editor
- **Severity:** High
- **Vulnerability Type:** Stored XSS
- **Platform:** HackerOne
- **Program:** Shopify
- **Bounty:** $5,000+
- **Description:** Attackers could inject malicious code directly into the HTML editor in /admin/product pages. The code would execute when any admin user viewed the product page.
- **How It Was Found:** Testing input fields in the product editor with HTML/JavaScript payloads.
- **Impact:** Compromise of admin sessions, potential full store takeover.
- **Key Takeaway:** Rich text editors and HTML editors are prime targets for stored XSS. Test both the visual editor and raw HTML input modes.
- **Source:** https://hackerone.com/reports/1147433

### 3. Stored XSS in Staff Member Name (Shopify)
- **Severity:** Medium
- **Vulnerability Type:** Stored XSS
- **Platform:** HackerOne
- **Program:** Shopify
- **Bounty:** $1,000+
- **Description:** A stored XSS was found in the staff member name field that would fire when viewed in Shopify's internal administration panel. The name field was not properly sanitized when rendered.
- **How It Was Found:** Injecting XSS payloads into profile name fields and observing where the name is rendered across the application.
- **Impact:** Code execution in the context of other admin users viewing staff lists.
- **Key Takeaway:** User profile fields (names, bios, etc.) that are displayed to other users are common stored XSS vectors. Test all fields that render user input.
- **Source:** https://hackerone.com/reports/946053

### 4. Stored XSS in Shopify Chat
- **Severity:** High
- **Vulnerability Type:** Stored XSS
- **Platform:** HackerOne
- **Program:** Shopify
- **Bounty:** $1,000+
- **Description:** A stored XSS vulnerability was discovered in Shopify's chat functionality where malicious scripts could be injected into chat messages and executed when viewed by support agents or other users.
- **How It Was Found:** Testing chat message input for HTML/JavaScript injection.
- **Impact:** Potential compromise of support agent sessions and access to sensitive customer data.
- **Key Takeaway:** Real-time messaging features often have different sanitization than traditional form inputs. Always test chat/messaging features separately.
- **Source:** https://hackerone.com/reports/756729

### 5. Unauthenticated Stored XSS on Shopify via Customer First Name
- **Severity:** High
- **Vulnerability Type:** Stored XSS
- **Platform:** HackerOne
- **Program:** Shopify
- **Bounty:** $1,500+
- **Description:** An unauthenticated stored XSS was found on *.myshopify.com through the customer's first name field in the checkout page. No authentication was required to inject the payload.
- **How It Was Found:** Testing checkout form fields with XSS payloads as an unauthenticated user.
- **Impact:** Attack could target store owners viewing customer details, potentially compromising admin accounts.
- **Key Takeaway:** Unauthenticated XSS vectors are especially valuable. Test all user-facing input fields that may be viewed by privileged users later.
- **Source:** https://hackerone.com/reports/189378

### 6. Stored XSS on X/Twitter Reports
- **Severity:** High
- **Vulnerability Type:** Stored XSS
- **Platform:** HackerOne
- **Program:** X / xAI (formerly Twitter)
- **Bounty:** $2,940+
- **Description:** Malicious scripts could be submitted on reports and would trigger when anyone checked the report. The stored payload executed in the context of authenticated users.
- **How It Was Found:** Testing report submission fields with various XSS payloads.
- **Impact:** Session hijacking of users viewing reports, potential account takeover.
- **Key Takeaway:** Content management and reporting features are often overlooked for XSS testing. Any feature where user input is stored and displayed to others is a potential target.
- **Source:** https://hackerone.com/reports/485748

### 7. Stored XSS in GitLab "Create Groups" Feature
- **Severity:** High
- **Vulnerability Type:** Stored XSS
- **Platform:** HackerOne
- **Program:** GitLab
- **Bounty:** $3,000
- **Description:** A stored XSS vulnerability was found in GitLab's group creation feature. An attacker could inject malicious JavaScript that would execute when other users viewed the group page.
- **How It Was Found:** Testing group name and description fields with XSS payloads.
- **Impact:** Code execution in the context of other GitLab users, potential access to private repositories.
- **Key Takeaway:** Group/organization creation features in SaaS platforms often have less strict input validation than user profile fields.
- **Source:** https://hackerone.com/reports/647130

### 8. Stored XSS in GitLab via Default Branch Name
- **Severity:** High
- **Vulnerability Type:** Stored XSS
- **Platform:** HackerOne
- **Program:** GitLab
- **Bounty:** $3,000+
- **Description:** Changing the default branch name in a project could inject arbitrary JavaScript that would execute when users visited the project's main page.
- **How It Was Found:** Testing branch naming with special characters and XSS payloads.
- **Impact:** Code execution in the context of any user viewing the project, potentially affecting all project members.
- **Key Takeaway:** Non-obvious input fields like branch names, tag names, and configuration values can be XSS vectors. Think beyond traditional form fields.
- **Source:** https://hackerone.com/reports/1256777

### 9. Stored XSS in GitLab via Customer Contact Fields
- **Severity:** High
- **Vulnerability Type:** Stored XSS
- **Platform:** HackerOne
- **Program:** GitLab
- **Bounty:** $13,950
- **Description:** Stored XSS was found in the new /add_contacts and /remove_contacts quick commands via Customer Contact firstname/lastname fields. The vulnerability existed in CRM-related features.
- **How It Was Found:** Testing quick command parameters with XSS payloads in GitLab's issue tracking CRM features.
- **Impact:** Code execution affecting GitLab users who interact with customer contacts, potentially compromising sensitive CRM data.
- **Key Takeaway:** Newer features and recently added functionality often have less mature security controls. Quick commands and API endpoints deserve special attention.
- **Source:** https://hackerone.com/reports/1256777

### 10. Stored XSS via Mermaid Prototype Pollution (GitLab)
- **Severity:** High
- **Vulnerability Type:** Stored XSS via Prototype Pollution
- **Platform:** HackerOne
- **Program:** GitLab
- **Bounty:** $3,000
- **Description:** A stored XSS vulnerability was found through Mermaid diagram rendering where prototype pollution could be leveraged to achieve script execution.
- **How It Was Found:** Analyzing Mermaid diagram parsing for prototype pollution vectors, then chaining with XSS.
- **Impact:** Code execution in the context of users viewing pages with Mermaid diagrams.
- **Key Takeaway:** Third-party libraries (like Mermaid for diagrams) introduce their own attack surface. Prototype pollution can often be chained with XSS for greater impact.
- **Source:** Referenced in GitLab HackerOne program disclosures

### 11. Stored XSS at linkpop.com (Shopify)
- **Severity:** Medium
- **Vulnerability Type:** Stored XSS
- **Platform:** HackerOne
- **Program:** Shopify
- **Bounty:** $1,000+
- **Description:** A stored XSS vulnerability was found on Shopify's Linkpop service, allowing injection of malicious scripts that execute when users visit affected Linkpop pages.
- **How It Was Found:** Testing Linkpop profile customization fields for injection points.
- **Impact:** Script execution on visitors to the affected Linkpop page, potential cookie theft.
- **Key Takeaway:** Subsidiary services and newly acquired products may have weaker security controls than the main platform.
- **Source:** https://hackerone.com/reports/1441988

### 12. Blind Stored XSS Against Employees (Lahitapiola)
- **Severity:** High
- **Vulnerability Type:** Blind Stored XSS
- **Platform:** HackerOne
- **Program:** Lahitapiola
- **Bounty:** $5,000
- **Description:** A blind stored XSS was discovered that affected internal employees when they viewed user-submitted data. The payload was not visible to the submitting user but executed in the employee's browser.
- **How It Was Found:** Using blind XSS payloads (e.g., XSS Hunter) in various user input fields, then waiting for callback notifications.
- **Impact:** Session hijacking of internal employees, access to internal admin panels and sensitive customer data.
- **Key Takeaway:** Blind XSS is extremely valuable. Use tools like XSS Hunter to plant payloads in fields that may be viewed by internal staff (support tickets, feedback forms, contact forms).
- **Source:** Referenced in HackerOne Lahitapiola program disclosures

### 13. Stored XSS in Acronis Cyber Protect Plan Name
- **Severity:** High
- **Vulnerability Type:** Stored XSS
- **Platform:** HackerOne
- **Program:** Acronis
- **Bounty:** $500+
- **Description:** A stored XSS vulnerability was found in the plan name field of Acronis Cyber Protect. The vulnerability was still exploitable in version 15.0.31791 released March 2023.
- **How It Was Found:** Testing plan/configuration name fields with XSS payloads.
- **Impact:** Code execution in the context of administrators managing backup plans.
- **Key Takeaway:** Enterprise/B2B software often has XSS in administrative configuration fields that are assumed to be trusted input.
- **Source:** https://hackerone.com/reports/1940788

---

## Reflected XSS Reports

### 14. Reflected XSS on Starbucks via ASP.Net URI Handling
- **Severity:** Medium
- **Vulnerability Type:** Reflected XSS
- **Platform:** HackerOne
- **Program:** Starbucks
- **Bounty:** $250+
- **Description:** A vulnerability in how ASP.Net handles URIs was exploited to perform reflected XSS on Starbucks web properties.
- **How It Was Found:** Testing URL parameters and path segments for reflection points, understanding ASP.Net-specific encoding behaviors.
- **Impact:** Cookie theft and session hijacking of Starbucks customers.
- **Key Takeaway:** Framework-specific behaviors (ASP.Net, Spring, Django, etc.) can introduce XSS vectors. Learn common framework quirks for better hunting.
- **Source:** https://hackerone.com/reports/881115

### 15. Reflected XSS on Starbucks Sign-in Page
- **Severity:** High
- **Vulnerability Type:** Reflected XSS
- **Platform:** HackerOne
- **Program:** Starbucks
- **Bounty:** $375+
- **Description:** A reflected XSS on the sign-in page allowed an attacker to execute JavaScript on a victim's account after authentication. The XSS was in a parameter that survived the login redirect.
- **How It Was Found:** Testing pre-auth pages and tracking parameter reflection through the authentication flow.
- **Impact:** Post-authentication JavaScript execution, leading to full account compromise.
- **Key Takeaway:** XSS on login/authentication pages is especially impactful. Test parameters that persist through the login flow (redirect URLs, state parameters).
- **Source:** https://hackerone.com/reports/438240

### 16. Reflected XSS on Starbucks 404 Error Pages via Double Encoding
- **Severity:** Medium
- **Vulnerability Type:** Reflected XSS
- **Platform:** HackerOne
- **Program:** Starbucks
- **Bounty:** $250+
- **Description:** Invalid page requests resulting in 404 error pages were vulnerable to reflected XSS when using double encoding. The application decoded URL-encoded characters twice, allowing XSS filter bypass.
- **How It Was Found:** Testing error pages with encoded payloads, specifically using double URL encoding to bypass WAF and application-level filters.
- **Impact:** Script execution in the context of Starbucks users who click malicious links.
- **Key Takeaway:** Double encoding is a powerful XSS filter bypass technique. Always test encoding variations: URL encoding, double encoding, HTML entity encoding, Unicode encoding.
- **Source:** https://hackerone.com/reports/629745

### 17. Reflected XSS on Ubiquiti Networks
- **Severity:** Medium
- **Vulnerability Type:** Reflected XSS
- **Platform:** HackerOne
- **Program:** Ubiquiti Inc.
- **Bounty:** $500+
- **Description:** A reflected cross-site scripting vulnerability was found on Ubiquiti's web properties where user input was reflected without proper sanitization.
- **How It Was Found:** Parameter fuzzing and testing reflection points.
- **Impact:** Cookie theft and phishing attacks against Ubiquiti users.
- **Key Takeaway:** Network equipment manufacturers often have web management interfaces with XSS vulnerabilities. Test both consumer-facing and admin-facing web properties.
- **Source:** https://hackerone.com/reports/208622

### 18. Reflected XSS on TikTok
- **Severity:** Medium
- **Vulnerability Type:** Reflected XSS
- **Platform:** HackerOne
- **Program:** TikTok
- **Bounty:** $500+
- **Description:** A URL parameter reflected its value without proper sanitization, allowing reflected XSS. The parameter value was directly inserted into the page without encoding.
- **How It Was Found:** Systematic testing of URL parameters for reflection, using tools like Burp Suite to identify unencoded reflections.
- **Impact:** Session hijacking and potential account takeover of TikTok users.
- **Key Takeaway:** Large platforms with many URL parameters are prime targets. Automated parameter discovery and reflection testing (using tools like kxss, dalfox, or reflected-xss-scanner) can efficiently identify these.
- **Source:** https://hackerone.com/reports/968082

### 19. Reflected XSS on HackerOne (hackerone.com)
- **Severity:** Medium
- **Vulnerability Type:** Reflected XSS
- **Platform:** HackerOne
- **Program:** HackerOne
- **Bounty:** $500+
- **Description:** A reflected XSS vulnerability was found on hackerone.com where user input was reflected back in the response without proper encoding.
- **How It Was Found:** Testing various endpoints on HackerOne's own platform for input reflection.
- **Impact:** Session hijacking of HackerOne users, potential access to vulnerability reports.
- **Key Takeaway:** Even security-focused platforms can have XSS vulnerabilities. No target should be assumed to be fully secure.
- **Source:** https://hackerone.com/reports/840759

### 20. Bypass Stored XSS on PayPal Sign-in Page
- **Severity:** Critical
- **Vulnerability Type:** Stored XSS (Filter Bypass)
- **Platform:** HackerOne
- **Program:** PayPal
- **Bounty:** $20,000
- **Description:** A bypass was found for a previously fixed stored XSS vulnerability (report #488147) on PayPal's sign-in page. The researcher found a new way to achieve XSS on the same endpoint, bypassing the original fix.
- **How It Was Found:** Analyzing the fix for the previous XSS vulnerability and finding alternative payloads that bypassed the new controls.
- **Impact:** Script execution on PayPal's sign-in page, potentially compromising user credentials and financial accounts.
- **Key Takeaway:** Always re-test previously fixed vulnerabilities. Bypasses for XSS fixes are common and often pay higher bounties. Study the fix and find alternative payloads.
- **Source:** Referenced in HackerOne Top 100 Paid Reports (Report #488147 bypass)

---

## DOM-Based XSS Reports

### 21. DOM XSS on HackerOne Careers Endpoint
- **Severity:** Medium
- **Vulnerability Type:** DOM-based XSS
- **Platform:** HackerOne
- **Program:** HackerOne
- **Bounty:** $500+
- **Description:** A DOM-based XSS vulnerability was found at HackerOne's careers endpoint where client-side JavaScript processed URL fragments or parameters unsafely, leading to script execution.
- **How It Was Found:** Analyzing client-side JavaScript code for dangerous sinks (innerHTML, document.write, eval) and testing DOM manipulation vectors.
- **Impact:** Code execution in authenticated user sessions on HackerOne.
- **Key Takeaway:** DOM XSS requires analyzing client-side JavaScript. Use browser dev tools and tools like DOM Invader (Burp Suite) to trace data flow from sources to sinks.
- **Source:** https://hackerone.com/reports/474656

### 22. XSS via Direct Message Deeplinks on Twitter
- **Severity:** High
- **Vulnerability Type:** DOM-based XSS
- **Platform:** HackerOne
- **Program:** Twitter (now X)
- **Bounty:** $2,940
- **Description:** An XSS vulnerability was found via Direct Message deeplinks where crafted URLs could execute JavaScript in the context of a Twitter user's session.
- **How It Was Found:** Testing deeplink URL schemes and their handling by the web application's JavaScript.
- **Impact:** Account compromise through DM-based phishing with automatic script execution.
- **Key Takeaway:** Mobile deeplink handlers and URL scheme processors on web platforms are often vulnerable to XSS. Test how the web app handles custom URL schemes.
- **Source:** Referenced in HackerOne Twitter/X program disclosures

### 23. XSS via SVG Icon Whitelist Bypass (Shopify)
- **Severity:** High
- **Vulnerability Type:** Stored/DOM XSS
- **Platform:** HackerOne
- **Program:** Shopify
- **Bounty:** $5,000
- **Description:** An XSS vulnerability was achieved on both $shop$.myshopify.com/admin/ and partners.shopify.com via a whitelist bypass in SVG icon handling for sales channel applications.
- **How It Was Found:** Analyzing the SVG whitelist implementation and finding bypass techniques to inject malicious SVG content.
- **Impact:** Code execution in admin panels of Shopify shops and the partners platform.
- **Key Takeaway:** Whitelist/allowlist bypasses are a rich hunting ground. Study how the application implements its allowlist and look for edge cases, encoding tricks, or alternative syntax.
- **Source:** https://hackerone.com/reports/231053

### 24. Possible XSS in Python (Internet Bug Bounty)
- **Severity:** Medium
- **Vulnerability Type:** XSS
- **Platform:** HackerOne
- **Program:** Internet Bug Bounty
- **Bounty:** $500+
- **Description:** A possible XSS vulnerability was identified in Python's standard library or related web tools that could lead to script execution in web contexts.
- **How It Was Found:** Source code review of Python's web-related modules for improper output encoding.
- **Impact:** Applications using the affected Python components could be vulnerable to XSS attacks.
- **Key Takeaway:** Vulnerabilities in language standard libraries have widespread impact. Review open-source code for security issues and report through appropriate channels.
- **Source:** https://hackerone.com/reports/2520694

### 25. CVE-2023-29489 XSS in cPanel (U.S. DoD)
- **Severity:** High
- **Vulnerability Type:** XSS
- **Platform:** HackerOne
- **Program:** U.S. Department of Defense
- **Bounty:** N/A (VDP)
- **Description:** A known CVE (CVE-2023-29489) for XSS in cPanel was found on a DoD asset. The vulnerability allowed script execution through the cPanel web interface.
- **How It Was Found:** Scanning DoD assets for known CVEs using vulnerability scanners and matching identified software versions against CVE databases.
- **Impact:** Script execution on DoD web infrastructure.
- **Key Takeaway:** Scanning for known CVEs on large attack surfaces (like the DoD) can yield valid findings. Keep up with new CVEs and test them against bug bounty targets quickly.
- **Source:** https://hackerone.com/reports/1982630

---

## XSS Hunting Methodology Summary

### Tools Commonly Used
- **Burp Suite** - Proxy, scanner, and DOM Invader for finding XSS
- **Dalfox** - Automated XSS scanner
- **kxss** - Reflected parameter discovery
- **XSS Hunter** - Blind XSS detection platform
- **Nuclei** - Template-based vulnerability scanner with XSS templates
- **ParamSpider** - Parameter discovery for reflection testing

### Common XSS Locations
1. Search fields and query parameters
2. Error pages (404, 500)
3. User profile fields (names, bios, addresses)
4. File upload (SVG, HTML files)
5. Rich text editors and HTML editors
6. Chat/messaging features
7. URL redirect parameters
8. API error messages reflected in UI
9. Third-party library rendering (Markdown, Mermaid, etc.)
10. Admin/internal panels (blind XSS)

### Key Bypass Techniques
- Double URL encoding
- Unicode encoding
- HTML entity encoding
- SVG-based payloads
- Prototype pollution chains
- Whitelist/allowlist bypasses
- Framework-specific quirks (ASP.Net, Angular, React dangerouslySetInnerHTML)

---

## Additional Reports (Expanded Collection)

### 26. Bypass for Stored XSS on PayPal Sign-in via Cache Poisoning
- **Severity**: Critical
- **Bounty**: $20,000
- **Program**: PayPal
- **Platform**: HackerOne
- **Description**: A bypass was found for a previous stored XSS fix (report #488147) on PayPal's sign-in page. The researcher discovered an alternative method to achieve stored XSS by exploiting cache poisoning on the same endpoint, leading to persistent script execution on PayPal's login page.
- **How Found**: Re-testing a previously fixed vulnerability by analyzing the patch and finding alternative injection vectors that bypassed the new controls.
- **Impact**: Credential theft and account takeover for any PayPal user visiting the sign-in page.
- **Key Takeaway**: Always re-test patched vulnerabilities. Bypasses for XSS fixes are common and often pay higher bounties than the original finding.
- **Source**: https://hackerone.com/reports/510152

### 27. Stored XSS on PayPal Sign-in via Cache Poisoning (Original)
- **Severity**: Critical
- **Bounty**: $18,900
- **Program**: PayPal
- **Platform**: HackerOne
- **Description**: A stored XSS vulnerability was achieved on PayPal's sign-in page through web cache poisoning. The attacker could poison the cache to serve malicious JavaScript to all visitors of the PayPal sign-in page.
- **How Found**: Testing cache behavior on authentication endpoints and identifying cache keys that could be manipulated to inject malicious content.
- **Impact**: Mass credential theft from PayPal's sign-in page affecting all visitors.
- **Key Takeaway**: Web cache poisoning combined with XSS can turn a reflected XSS into a stored one with massive reach. Study cache key behavior and unkeyed inputs.
- **Source**: https://hackerone.com/reports/488147

### 28. Stored XSS in GitLab Markdown via DesignReferenceFilter
- **Severity**: Critical
- **Bounty**: $16,000
- **Program**: GitLab
- **Platform**: HackerOne
- **Description**: A stored XSS vulnerability was found in GitLab's markdown rendering through the DesignReferenceFilter. Malicious content in design references could execute JavaScript when other users viewed the markdown content.
- **How Found**: Analyzing GitLab's markdown parsing pipeline, specifically the DesignReferenceFilter component, for injection points.
- **Impact**: Code execution in the context of any GitLab user viewing the affected markdown content, potentially exposing private repository data.
- **Key Takeaway**: Markdown rendering pipelines with custom filters are rich attack surfaces. Each filter in the pipeline can introduce new XSS vectors.
- **Source**: https://hackerone.com/reports/1212067

### 29. Stored XSS via Kroki Diagram in GitLab
- **Severity**: High
- **Bounty**: $13,950
- **Program**: GitLab
- **Platform**: HackerOne
- **Description**: A stored XSS was achieved through GitLab's Kroki diagram integration. Malicious diagram definitions could inject JavaScript that executed when rendered in the browser.
- **How Found**: Testing third-party diagram rendering integrations (Kroki) with payloads designed to escape the diagram context and inject scripts.
- **Impact**: Script execution for any user viewing pages containing the malicious Kroki diagram.
- **Key Takeaway**: Third-party rendering integrations (Kroki, Mermaid, PlantUML) are frequent XSS vectors because they convert untrusted input into HTML/SVG.
- **Source**: https://hackerone.com/reports/1731349

### 30. Stored XSS in GitLab Notes with CSP Bypass
- **Severity**: High
- **Bounty**: $13,950
- **Program**: GitLab
- **Platform**: HackerOne
- **Description**: A stored XSS vulnerability was found in GitLab Notes (comments) that included a Content Security Policy bypass for gitlab.com. The CSP bypass made the vulnerability exploitable even on the production instance.
- **How Found**: Finding an XSS injection point in notes and then researching CSP bypass techniques specific to GitLab's CSP configuration.
- **Impact**: Full JavaScript execution on gitlab.com despite CSP protections, leading to potential account takeover.
- **Key Takeaway**: CSP is not a silver bullet. Research target-specific CSP bypass techniques (JSONP endpoints, allowed CDNs, script gadgets) to make XSS exploitable.
- **Source**: https://hackerone.com/reports/1481207

### 31. XSS in ZenTao Integration (GitLab)
- **Severity**: High
- **Bounty**: $13,950
- **Program**: GitLab
- **Platform**: HackerOne
- **Description**: An XSS vulnerability was found in GitLab's ZenTao project management integration that affected self-hosted instances without strict CSP policies.
- **How Found**: Testing integration features between GitLab and third-party project management tools for input sanitization issues.
- **Impact**: JavaScript execution on self-hosted GitLab instances, potentially compromising source code and CI/CD pipelines.
- **Key Takeaway**: Integration points between platforms are high-value XSS targets. Self-hosted instances often lack the CSP protections of SaaS versions.
- **Source**: https://hackerone.com/reports/1542510

### 32. XSS at jamfpro.shopifycloud.com
- **Severity**: High
- **Bounty**: $9,400
- **Program**: Shopify
- **Platform**: HackerOne
- **Description**: An XSS vulnerability was discovered on Shopify's cloud infrastructure at jamfpro.shopifycloud.com, allowing script execution in the context of Shopify Cloud services.
- **How Found**: Subdomain enumeration of shopifycloud.com followed by testing discovered endpoints for XSS.
- **Impact**: Script execution on Shopify's cloud management infrastructure.
- **Key Takeaway**: Subdomain enumeration on cloud infrastructure domains can reveal less-hardened services. Cloud management interfaces are valuable targets.
- **Source**: https://hackerone.com/reports/1444682

### 33. XSS in Steam React Chat Client
- **Severity**: High
- **Bounty**: $7,500
- **Program**: Valve
- **Platform**: HackerOne
- **Description**: An XSS vulnerability was found in Steam's React-based chat client. Despite React's built-in XSS protections, a bypass was found that allowed script execution in the chat context.
- **How Found**: Analyzing React component rendering in Steam's chat for unsafe patterns like dangerouslySetInnerHTML or URL scheme handling.
- **Impact**: Account compromise of Steam users through malicious chat messages, potentially leading to game inventory theft.
- **Key Takeaway**: React apps are not immune to XSS. Look for dangerouslySetInnerHTML, href/src attributes with user input, and custom HTML rendering.
- **Source**: https://hackerone.com/reports/409850

### 34. Stored XSS in developer.uber.com
- **Severity**: High
- **Bounty**: $7,500
- **Program**: Uber
- **Platform**: HackerOne
- **Description**: A stored XSS vulnerability was found on Uber's developer portal. Malicious scripts could be stored and executed when other developers or admins viewed the affected content.
- **How Found**: Testing input fields on Uber's developer documentation and API management portal.
- **Impact**: Compromise of developer accounts, potential access to API keys and OAuth credentials.
- **Key Takeaway**: Developer portals and documentation platforms often have rich text input that may be vulnerable to stored XSS.
- **Source**: https://hackerone.com/reports/131450

### 35. Stored XSS on Any Page in Most Uber Domains
- **Severity**: High
- **Bounty**: $6,000
- **Program**: Uber
- **Platform**: HackerOne
- **Description**: A stored XSS vulnerability affected multiple Uber domains, allowing persistent script injection on virtually any page across most of Uber's web properties.
- **How Found**: Identifying a shared component or template used across multiple Uber domains that had an XSS vulnerability.
- **Impact**: Wide-reaching XSS affecting riders, drivers, and internal Uber staff across multiple domains.
- **Key Takeaway**: Shared components and templates across multiple domains can amplify the impact of a single XSS vulnerability dramatically.
- **Source**: https://hackerone.com/reports/217739

### 36. HEY.com Email Stored XSS
- **Severity**: High
- **Bounty**: $5,000
- **Program**: Basecamp
- **Platform**: HackerOne
- **Description**: A stored XSS was found in Basecamp's HEY.com email service. Malicious scripts in email content could execute when recipients viewed the email in the HEY web client.
- **How Found**: Sending crafted emails with XSS payloads to a HEY.com address and testing how the web client renders email content.
- **Impact**: Account takeover of HEY.com email users, access to all stored emails and contacts.
- **Key Takeaway**: Email clients that render HTML are prime XSS targets. Test with various HTML elements, CSS injection, and SVG payloads in email content.
- **Source**: https://hackerone.com/reports/982291

### 37. Redirect Parameter XSS on accounts.reddit.com
- **Severity**: High
- **Bounty**: $5,000
- **Program**: Reddit
- **Platform**: HackerOne
- **Description**: A redirect parameter on Reddit's accounts subdomain allowed XSS execution. The redirect_uri parameter was not properly sanitized, enabling JavaScript injection.
- **How Found**: Testing OAuth and authentication redirect parameters for JavaScript URI injection (javascript: protocol).
- **Impact**: Account takeover of Reddit users through crafted authentication links.
- **Key Takeaway**: Redirect parameters in OAuth and authentication flows are high-value XSS targets. Test for javascript: URI, data: URI, and other protocol handlers.
- **Source**: https://hackerone.com/reports/1962645

### 38. RichText Parser XSS in Reddit Scheduled Posts
- **Severity**: High
- **Bounty**: $5,000
- **Program**: Reddit
- **Platform**: HackerOne
- **Description**: A vulnerability in Reddit's RichText parser for scheduled posts allowed XSS execution. The parser failed to properly sanitize certain input patterns when rendering scheduled post content.
- **How Found**: Testing the scheduled post feature with various RichText formatting and injection payloads.
- **Impact**: XSS execution in the context of Reddit moderators and users viewing scheduled posts.
- **Key Takeaway**: Rich text parsers and WYSIWYG editors are common XSS vectors. Test both the rendered output and the raw format for injection points.
- **Source**: https://hackerone.com/reports/1930763

### 39. Reflected XSS on sh.reddit.com
- **Severity**: High
- **Bounty**: $5,000
- **Program**: Reddit
- **Platform**: HackerOne
- **Description**: A reflected XSS was found on Reddit's short URL domain (sh.reddit.com) where user input was reflected without proper encoding.
- **How Found**: Testing Reddit's URL shortener and auxiliary domains for reflection points.
- **Impact**: Session hijacking of Reddit users who click malicious short links.
- **Key Takeaway**: Auxiliary domains and URL shorteners operated by the target are often less hardened than the main domain.
- **Source**: https://hackerone.com/reports/1549206

### 40. Reflected XSS on Pangle Endpoint (TikTok)
- **Severity**: High
- **Bounty**: $5,000
- **Program**: TikTok
- **Platform**: HackerOne
- **Description**: A reflected XSS was found on TikTok's Pangle advertising endpoint. The vulnerability allowed script execution through unvalidated parameters on the ad platform.
- **How Found**: Testing TikTok's advertising and partner platform endpoints for parameter reflection.
- **Impact**: Potential compromise of advertiser accounts and access to advertising campaign data.
- **Key Takeaway**: Advertising and partner platforms are often separate codebases with different security maturity levels.
- **Source**: https://hackerone.com/reports/2352968

### 41. One-Click Account Hijack via Apple Sign-in XSS (Reddit)
- **Severity**: Critical
- **Bounty**: Not disclosed
- **Program**: Reddit
- **Platform**: HackerOne
- **Description**: A one-click account hijack was achieved by combining a response-type switch in Apple sign-in with an XSS on redditmedia.com. The href leaked to the XSS page, allowing the attacker to steal Apple OAuth tokens.
- **How Found**: Analyzing the Apple sign-in OAuth flow for response_type parameter manipulation and chaining with an existing XSS on a related domain.
- **Impact**: Complete account takeover of any Reddit user using Apple sign-in with a single click.
- **Key Takeaway**: OAuth flow vulnerabilities chained with XSS on related domains can lead to devastating account takeover. Always map out the full OAuth flow.
- **Source**: https://hackerone.com/reports/1567186

### 42. Reflected XSS in LY Corporation OAuth2 Login Flow
- **Severity**: High
- **Bounty**: $1,989
- **Program**: LY Corporation (LINE)
- **Platform**: HackerOne
- **Description**: A reflected XSS was found in the OAuth2 login flow of LY Corporation (formerly LINE). The vulnerability existed in parameters processed during the authentication redirect.
- **How Found**: Intercepting and analyzing the OAuth2 login flow parameters for reflection and injection points.
- **Impact**: Token theft and account takeover of LINE users during the authentication process.
- **Key Takeaway**: OAuth2 login flows involve multiple redirects and parameters that are often reflected. Test state, redirect_uri, and error parameters.
- **Source**: https://hackerone.com/reports/697099

### 43. Reflected XSS and Sensitive Data Exposure on Uber (lioncityrentals.com.sg)
- **Severity**: High
- **Bounty**: $4,000
- **Program**: Uber
- **Platform**: HackerOne
- **Description**: A reflected XSS on lioncityrentals.com.sg (an Uber acquisition) also exposed sensitive data including payment details. The XSS and data exposure combined for a high-impact finding.
- **How Found**: Testing acquired company domains still linked to Uber's infrastructure for common vulnerabilities.
- **Impact**: XSS combined with payment data exposure on an Uber-owned domain.
- **Key Takeaway**: Acquired companies and subsidiary domains often retain legacy code with vulnerabilities. Research target company acquisitions for expanded attack surface.
- **Source**: https://hackerone.com/reports/340431

### 44. Stored XSS on Uber login.uber.com via redirect_uri
- **Severity**: High
- **Bounty**: $3,000
- **Program**: Uber
- **Platform**: HackerOne
- **Description**: A stored XSS was found on Uber's login endpoint via the redirect_uri parameter on the OAuth authorization page. The XSS persisted in the authentication flow.
- **How Found**: Testing the redirect_uri parameter in Uber's OAuth flow with various JavaScript and data URI payloads.
- **Impact**: Credential theft and session hijacking during Uber's authentication process.
- **Key Takeaway**: OAuth redirect_uri parameters deserve extensive testing with various URI schemes and encoding techniques.
- **Source**: https://hackerone.com/reports/392106

### 45. Reflected XSS on TikTok Website
- **Severity**: High
- **Bounty**: $3,000
- **Program**: TikTok
- **Platform**: HackerOne
- **Description**: A reflected XSS was found on TikTok's main website where a URL parameter's value was reflected in the page without proper sanitization.
- **How Found**: Systematic parameter fuzzing on TikTok's web endpoints.
- **Impact**: Session hijacking and potential account takeover of TikTok users.
- **Key Takeaway**: Large social media platforms with many endpoints and parameters offer extensive reflected XSS attack surface.
- **Source**: https://hackerone.com/reports/1378413

### 46. Reflected XSS on Shopify online-store-git.shopifycloud.com
- **Severity**: High
- **Bounty**: $3,500
- **Program**: Shopify
- **Platform**: HackerOne
- **Description**: A reflected XSS was found on Shopify's online store Git infrastructure at shopifycloud.com. The internal development infrastructure exposed an XSS vulnerability.
- **How Found**: Subdomain discovery on shopifycloud.com and testing discovered development/staging endpoints.
- **Impact**: Potential access to Shopify's development infrastructure and merchant store code.
- **Key Takeaway**: Development and staging environments exposed on cloud infrastructure are often less hardened and provide valuable targets.
- **Source**: https://hackerone.com/reports/1410459

### 47. Cross-site Scripting in GitLab RDoc Wiki Pages
- **Severity**: High
- **Bounty**: $3,500
- **Program**: GitLab
- **Platform**: HackerOne
- **Description**: A stored XSS was found in GitLab's RDoc wiki page rendering. RDoc markup could be crafted to inject JavaScript that executed when users viewed the wiki page.
- **How Found**: Testing various wiki markup formats (RDoc, AsciiDoc, Markdown) for XSS injection in GitLab wiki pages.
- **Impact**: Code execution for any user viewing the affected wiki page, potentially affecting all project contributors.
- **Key Takeaway**: Multiple markup language parsers (Markdown, RDoc, AsciiDoc, reStructuredText) each have their own XSS attack surface. Test all supported formats.
- **Source**: https://hackerone.com/reports/662287

### 48. Stored XSS in GitLab Custom Emoji
- **Severity**: High
- **Bounty**: $3,000
- **Program**: GitLab
- **Platform**: HackerOne
- **Description**: A stored XSS vulnerability was found through GitLab's custom emoji feature. Malicious content in custom emoji definitions could execute JavaScript when the emoji was rendered.
- **How Found**: Testing the custom emoji upload and rendering pipeline for XSS injection points.
- **Impact**: Script execution whenever the malicious custom emoji was displayed to any user.
- **Key Takeaway**: Custom asset upload features (emojis, stickers, icons) can be XSS vectors if the uploaded content is rendered as HTML/SVG.
- **Source**: https://hackerone.com/reports/1198517

### 49. XSS in Request Approvals (GitLab)
- **Severity**: High
- **Bounty**: $3,000
- **Program**: GitLab
- **Platform**: HackerOne
- **Description**: An XSS vulnerability was found in GitLab's merge request approval feature. Malicious input in the approval workflow could inject scripts.
- **How Found**: Testing the merge request approval process inputs for script injection.
- **Impact**: Script execution in the context of code reviewers and approvers, potentially compromising the code review process.
- **Key Takeaway**: Workflow and approval features involve multiple users viewing shared data, making them attractive stored XSS targets.
- **Source**: https://hackerone.com/reports/402658

### 50. Stored XSS on TikTok Ads
- **Severity**: High
- **Bounty**: $2,500
- **Program**: TikTok
- **Platform**: HackerOne
- **Description**: A stored XSS was found on TikTok's advertising platform (ads.tiktok.com). Malicious scripts could be stored in ad configurations and execute when viewed by other users of the ad platform.
- **How Found**: Testing ad creation and management fields on TikTok's advertising dashboard.
- **Impact**: Compromise of advertiser accounts, potential manipulation of advertising campaigns and budgets.
- **Key Takeaway**: Advertising platforms handle financial transactions and campaign data, making stored XSS especially impactful.
- **Source**: https://hackerone.com/reports/1504202

### 51. DOM XSS on ads.tiktok.com
- **Severity**: High
- **Bounty**: $2,500
- **Program**: TikTok
- **Platform**: HackerOne
- **Description**: A DOM-based XSS was found on TikTok's advertising platform where client-side JavaScript processed URL data unsafely, writing to a dangerous DOM sink.
- **How Found**: Analyzing client-side JavaScript on TikTok's ad platform for DOM sources and sinks using browser developer tools and DOM Invader.
- **Impact**: Session hijacking of TikTok advertisers, access to campaign and billing data.
- **Key Takeaway**: DOM XSS requires different tools than server-side XSS. Use DOM Invader (Burp Suite), browser dev tools, and source-to-sink tracing.
- **Source**: https://hackerone.com/reports/1549451

### 52. DOM XSS via postMessage on Upserve Inventory
- **Severity**: High
- **Bounty**: $2,500
- **Program**: Upserve
- **Platform**: HackerOne
- **Description**: A DOM-based XSS was found via postMessage handling on Upserve's inventory management login page. The JavaScript event listener did not validate the message origin.
- **How Found**: Analyzing postMessage event listeners on the login page for missing origin validation and unsafe data handling.
- **Impact**: Account takeover through crafted postMessage payloads from an attacker-controlled window.
- **Key Takeaway**: postMessage handlers without origin validation are a common DOM XSS vector. Search JavaScript for addEventListener('message') and check for origin checks.
- **Source**: https://hackerone.com/reports/603764

### 53. IE-Only Stored XSS via Program Asset Identifier (HackerOne)
- **Severity**: High
- **Bounty**: $2,500
- **Program**: HackerOne
- **Platform**: HackerOne
- **Description**: A stored XSS was found on HackerOne's platform through the Program Asset identifier field. The vulnerability was exploitable only in Internet Explorer due to IE-specific HTML parsing behavior.
- **How Found**: Testing input fields with browser-specific XSS payloads, particularly IE-specific vectors like CSS expressions and VML.
- **Impact**: Script execution for IE users viewing program pages on HackerOne.
- **Key Takeaway**: Browser-specific XSS payloads can bypass filters designed for modern browsers. Test with IE/Edge-specific vectors for broader coverage.
- **Source**: https://hackerone.com/reports/449351

### 54. Stored XSS via Synthetics Monitor Tag (New Relic)
- **Severity**: High
- **Bounty**: $2,123
- **Program**: New Relic
- **Platform**: HackerOne
- **Description**: A stored XSS was found via the tag key value of a Synthetics monitor when viewing an Insights dashboard with filtering enabled. The tag value was not properly sanitized when rendered in the dashboard.
- **How Found**: Testing tag/label fields in monitoring tools for script injection and observing rendering on dashboards.
- **Impact**: Script execution for New Relic users viewing dashboards with malicious monitor tags.
- **Key Takeaway**: Metadata fields like tags, labels, and categories are often overlooked for XSS but are rendered in multiple contexts (dashboards, reports, filters).
- **Source**: https://hackerone.com/reports/1067321

### 55. Possible XSS on Stripe
- **Severity**: High
- **Bounty**: $2,000
- **Program**: Stripe
- **Platform**: HackerOne
- **Description**: A possible XSS vulnerability was found on Stripe's platform without requiring a Content Security Policy bypass. The vulnerability existed in payment-related functionality.
- **How Found**: Testing Stripe's payment forms and checkout flows for XSS injection points.
- **Impact**: Potential compromise of payment data and merchant accounts on Stripe's platform.
- **Key Takeaway**: Payment processors are extremely high-value targets for XSS due to the financial data they handle.
- **Source**: https://hackerone.com/reports/1804177

### 56. XSS While Logging in via Google (Shopify)
- **Severity**: High
- **Bounty**: $1,750
- **Program**: Shopify
- **Platform**: HackerOne
- **Description**: An XSS vulnerability was found in Shopify's Google login flow. The vulnerability existed in how the OAuth callback processed data from Google's authentication response.
- **How Found**: Testing the Google OAuth integration flow for injection points in callback parameters and state values.
- **Impact**: Account takeover of Shopify merchants who use Google sign-in.
- **Key Takeaway**: Social login integrations (Google, Facebook, Apple, GitHub) add complexity and potential XSS vectors in the OAuth callback handling.
- **Source**: https://hackerone.com/reports/691611

### 57. XSS and Open Redirect on MoPub Login (Twitter/X)
- **Severity**: High
- **Bounty**: $1,540
- **Program**: X / xAI (formerly Twitter)
- **Platform**: HackerOne
- **Description**: Both an XSS and open redirect were found on Twitter's MoPub mobile advertising platform login page. The vulnerabilities could be chained for account takeover.
- **How Found**: Testing the login page redirect parameters for both open redirect and JavaScript injection.
- **Impact**: Account takeover of MoPub advertisers and access to mobile advertising campaign data.
- **Key Takeaway**: Open redirects and XSS often coexist and can be chained. An open redirect can help bypass domain-based XSS filters.
- **Source**: https://hackerone.com/reports/683298

### 58. Stored XSS in 8x8 API
- **Severity**: High
- **Bounty**: $1,337
- **Program**: 8x8
- **Platform**: HackerOne
- **Description**: A stored XSS was found in 8x8's API endpoint. Malicious scripts stored through the API would execute when the data was rendered in the web interface.
- **How Found**: Testing API endpoints for XSS by injecting payloads through API calls and observing how the data was rendered in the frontend.
- **Impact**: Script execution for 8x8 users viewing data submitted through the vulnerable API endpoint.
- **Key Takeaway**: APIs that accept user input which is later rendered in a web UI are stored XSS targets. Test API inputs even if the API itself returns JSON.
- **Source**: https://hackerone.com/reports/2078490

### 59. Chaining CSRF Token Leakage to Stored XSS and Account Takeover
- **Severity**: Critical
- **Bounty**: $1,100
- **Program**: InnoGames
- **Platform**: HackerOne
- **Description**: A chain of vulnerabilities was found on InnoGames' Tribal Wars: CSRF token leakage was chained with stored XSS to achieve full account takeover.
- **How Found**: Discovering a CSRF token leak, then using it to inject a stored XSS payload that automated the account takeover process.
- **Impact**: Full account takeover of game players including in-game assets and account data.
- **Key Takeaway**: Chaining lower-severity vulnerabilities (information disclosure + XSS) can create critical-severity chains. Always look for ways to escalate.
- **Source**: https://hackerone.com/reports/604120

### 60. Blind XSS on Image Upload (CS Money)
- **Severity**: High
- **Bounty**: $1,000
- **Program**: CS Money
- **Platform**: HackerOne
- **Description**: A blind XSS was found through the image upload feature on CS Money. The XSS payload in the uploaded image metadata executed when staff viewed the upload in an admin panel.
- **How Found**: Embedding XSS payloads in image metadata (EXIF data, filenames) and using XSS Hunter to detect blind execution.
- **Impact**: Compromise of admin panel sessions, access to user trading data and financial information.
- **Key Takeaway**: Image upload metadata (EXIF, filename, content-type) can carry XSS payloads. Use blind XSS tools to detect execution in admin panels.
- **Source**: https://hackerone.com/reports/1010466

### 61. Reflected XSS on Bumble
- **Severity**: Medium
- **Bounty**: $1,000
- **Program**: Bumble
- **Platform**: HackerOne
- **Description**: A reflected XSS was found on Bumble's web application where user input from URL parameters was reflected without proper encoding.
- **How Found**: Testing URL parameters on Bumble's web endpoints for reflection points.
- **Impact**: Session hijacking and potential account takeover of Bumble dating app users.
- **Key Takeaway**: Dating and social apps handle sensitive personal data, making XSS findings particularly impactful from a privacy perspective.
- **Source**: https://hackerone.com/reports/739601

### 62. Reflected XSS on Razer Pay Escalated to Account Takeover
- **Severity**: High
- **Bounty**: $750
- **Program**: Razer
- **Platform**: HackerOne
- **Description**: A reflected XSS on Razer's payment platform (pay.gold.razer.com) was escalated to full account takeover by stealing session tokens through the injected script.
- **How Found**: Finding a reflected XSS on the payment page and crafting a payload to exfiltrate session cookies and authentication tokens.
- **Impact**: Account takeover and potential financial fraud on Razer's payment platform.
- **Key Takeaway**: Always try to escalate XSS to account takeover by stealing session tokens, CSRF tokens, or OAuth codes. Escalation significantly increases bounty payouts.
- **Source**: https://hackerone.com/reports/723060

### 63. Stored XSS in Razer Pay Order Payment
- **Severity**: High
- **Bounty**: $1,500
- **Program**: Razer
- **Platform**: HackerOne
- **Description**: A stored XSS was found in Razer's payment system through order payment data. The malicious script persisted and executed when payment details were viewed.
- **How Found**: Testing order and payment fields for script injection on Razer's payment platform.
- **Impact**: Financial data theft and account compromise on a payment processing platform.
- **Key Takeaway**: Payment and e-commerce platforms should be tested thoroughly for stored XSS in order details, product names, and transaction descriptions.
- **Source**: https://hackerone.com/reports/706916

### 64. Reflected XSS on transact.playstation.com via postMessage
- **Severity**: High
- **Bounty**: $1,000
- **Program**: PlayStation
- **Platform**: HackerOne
- **Description**: A reflected XSS was found on PlayStation's transaction page through postMessage communication from the opening window. The transaction page accepted messages without proper origin validation.
- **How Found**: Analyzing cross-window communication on PlayStation's payment pages for postMessage-based injection.
- **Impact**: Session theft on PlayStation's payment platform, potential unauthorized purchases.
- **Key Takeaway**: Payment pages that use postMessage for cross-frame/cross-window communication are particularly dangerous if origin validation is missing.
- **Source**: https://hackerone.com/reports/900619

### 65. Stored XSS and SSRF in Lark Docs
- **Severity**: High
- **Bounty**: $3,000
- **Program**: Lark Technologies
- **Platform**: HackerOne
- **Description**: Both stored XSS and SSRF were found in Lark Docs. The XSS component allowed script execution through document content that was not properly sanitized.
- **How Found**: Testing document creation and editing features in Lark Docs for HTML/JavaScript injection.
- **Impact**: Compromise of Lark Docs users viewing malicious documents, plus server-side request capabilities.
- **Key Takeaway**: Document collaboration platforms (Lark, Notion, Google Docs alternatives) are rich targets for both XSS and SSRF due to their document rendering capabilities.
- **Source**: https://hackerone.com/reports/892049

### 66. Panorama UI XSS Leading to RCE via Kick/Disconnect Message (Valve)
- **Severity**: Critical
- **Bounty**: Not disclosed
- **Program**: Valve
- **Platform**: HackerOne
- **Description**: An XSS in Valve's Panorama UI could be escalated to Remote Code Execution through the game's kick/disconnect message handling. The game UI rendered HTML in system messages.
- **How Found**: Testing in-game UI message rendering for HTML injection, then escalating to RCE through the game engine's JavaScript bridge.
- **Impact**: Remote code execution on other players' computers through in-game messages.
- **Key Takeaway**: Desktop applications and game clients that use web rendering engines (CEF, Electron, Panorama) can have XSS that escalates to RCE.
- **Source**: https://hackerone.com/reports/631956

### 67. Stored XSS in WordPress Core
- **Severity**: High
- **Bounty**: Not disclosed
- **Program**: WordPress
- **Platform**: HackerOne
- **Description**: A stored XSS vulnerability was found in WordPress core, affecting all WordPress installations running the vulnerable version. The vulnerability existed in the content rendering system.
- **How Found**: Source code review of WordPress core, specifically the content sanitization and rendering pipeline.
- **Impact**: Script execution on millions of WordPress sites, potentially affecting site administrators and visitors.
- **Key Takeaway**: Core CMS vulnerabilities have massive impact due to the number of installations. WordPress, Drupal, and Joomla core code is worth reviewing for XSS.
- **Source**: https://hackerone.com/reports/643908

### 68. DOM XSS on DuckDuckGo Search
- **Severity**: Medium
- **Bounty**: Not disclosed
- **Program**: DuckDuckGo
- **Platform**: HackerOne
- **Description**: A DOM-based XSS was found in DuckDuckGo's search functionality where search parameters were processed unsafely by client-side JavaScript.
- **How Found**: Analyzing DuckDuckGo's client-side JavaScript for DOM sources (location.hash, location.search) flowing into dangerous sinks.
- **Impact**: Script execution in the context of DuckDuckGo users, potentially compromising search privacy.
- **Key Takeaway**: Privacy-focused services are ironic but valuable XSS targets. Search functionality is a classic DOM XSS location.
- **Source**: https://hackerone.com/reports/868934

### 69. Yelp XSS Leading to Account Takeover via Login Keylogger
- **Severity**: Critical
- **Bounty**: Not disclosed
- **Program**: Yelp
- **Platform**: HackerOne
- **Description**: An XSS on yelp.com was escalated to account takeover by using the injected script as a keylogger on the login page and chaining with Google account linking.
- **How Found**: Finding an XSS on Yelp and developing a sophisticated payload that injected a keylogger on the login form.
- **Impact**: Full credential theft and account takeover of Yelp users, including linked Google accounts.
- **Key Takeaway**: Escalate XSS with creative payloads: keyloggers on login forms, CSRF for account linking, and OAuth token theft can dramatically increase impact.
- **Source**: https://hackerone.com/reports/2010530

### 70. Blind XSS on Twitter Internal Big Data Panel
- **Severity**: High
- **Bounty**: Not disclosed
- **Program**: X / xAI (formerly Twitter)
- **Platform**: HackerOne
- **Description**: A blind XSS was discovered that fired on Twitter's internal Big Data analytics panel. The payload was injected through public-facing features but executed in an internal admin tool.
- **How Found**: Deploying blind XSS payloads (via XSS Hunter or similar) across various Twitter input fields and waiting for internal panel triggers.
- **Impact**: Access to Twitter's internal Big Data analytics, potentially exposing user analytics, trending algorithms, and internal metrics.
- **Key Takeaway**: Blind XSS targeting internal panels can access highly sensitive internal tools. Deploy blind XSS payloads broadly and monitor for callbacks.
- **Source**: https://hackerone.com/reports/1207040

### 71. Blind XSS on Twitter Internal Jira Panel
- **Severity**: High
- **Bounty**: Not disclosed
- **Program**: X / xAI (formerly Twitter)
- **Platform**: HackerOne
- **Description**: A blind XSS was found that executed on Twitter's internal Jira panel, allowing exfiltration of hacker reports and other sensitive internal data from the issue tracking system.
- **How Found**: Injecting blind XSS payloads through bug report submissions and Twitter features that fed into the internal Jira system.
- **Impact**: Exfiltration of internal security reports, bug tracker data, and sensitive development information.
- **Key Takeaway**: Bug report forms and support tickets often feed into internal issue trackers (Jira, ServiceNow). Blind XSS in these fields can access internal development data.
- **Source**: https://hackerone.com/reports/1369674

### 72. Account Takeover via Cookie Manipulation and XSS (Grammarly)
- **Severity**: High
- **Bounty**: Not disclosed
- **Program**: Superhuman (formerly Grammarly)
- **Platform**: HackerOne
- **Description**: An account takeover was achieved by combining cookie manipulation with XSS on Grammarly's platform. The XSS allowed modifying authentication cookies to hijack accounts.
- **How Found**: Finding an XSS vulnerability and analyzing cookie handling to chain the XSS with cookie manipulation for account takeover.
- **Impact**: Full account takeover of Grammarly users, access to all stored documents and writing history.
- **Key Takeaway**: Cookie manipulation through XSS can lead to account takeover even without httpOnly cookies. Analyze all cookies set by the application.
- **Source**: https://hackerone.com/reports/534450

### 73. Persistent XSS on Keybase via Sigchain Payload
- **Severity**: High
- **Bounty**: Not disclosed
- **Program**: Keybase
- **Platform**: HackerOne
- **Description**: A persistent XSS was found on keybase.io through the "payload" field in the sigchain signature template. The payload data was rendered without proper sanitization.
- **How Found**: Analyzing Keybase's sigchain verification page templates for user-controlled data rendered as HTML.
- **Impact**: Script execution for any user viewing the affected sigchain, potentially compromising cryptographic key management.
- **Key Takeaway**: Cryptographic and security-focused applications can have XSS in their verification and display pages. Don't assume security tools are secure.
- **Source**: https://hackerone.com/reports/245296

### 74. Stored XSS on Imgur Profile
- **Severity**: High
- **Bounty**: Not disclosed
- **Program**: Imgur
- **Platform**: HackerOne
- **Description**: A stored XSS was found in Imgur user profiles where malicious scripts could be stored in profile fields and executed when other users viewed the profile.
- **How Found**: Testing Imgur profile fields (bio, links, display name) with XSS payloads.
- **Impact**: Session hijacking of Imgur users viewing the malicious profile, potential mass exploitation via popular profiles.
- **Key Takeaway**: Social media profile fields are classic stored XSS targets. Test all editable profile fields including less obvious ones like location, website URL, and custom fields.
- **Source**: https://hackerone.com/reports/484434

### 75. Web Cache Poisoning to Stored XSS on Glassdoor
- **Severity**: High
- **Bounty**: Not disclosed
- **Program**: Glassdoor
- **Platform**: HackerOne
- **Description**: Web cache poisoning was used to achieve stored XSS on Glassdoor. By poisoning the cache with malicious content, the XSS payload was served to all visitors requesting the same cached resource.
- **How Found**: Identifying unkeyed HTTP headers or parameters that were reflected in cached responses and injecting XSS payloads.
- **Impact**: Mass XSS affecting all visitors who received the poisoned cached response, potentially exposing salary and company review data.
- **Key Takeaway**: Web cache poisoning can amplify XSS from affecting a single user to affecting all visitors. Use tools like Param Miner to find unkeyed inputs.
- **Source**: https://hackerone.com/reports/1424094

### 76. Stored XSS in Shopify Private Messages
- **Severity**: High
- **Bounty**: $1,000
- **Program**: Shopify
- **Platform**: HackerOne
- **Description**: A stored XSS was found in Shopify's private messaging feature. Malicious scripts in messages executed when the recipient opened the message.
- **How Found**: Testing the private message input with various XSS payloads, including those that bypass message sanitization.
- **Impact**: Account compromise of Shopify merchants through malicious messages.
- **Key Takeaway**: Private messaging features in any platform are stored XSS targets. The private context may lead developers to apply less strict sanitization.
- **Source**: https://hackerone.com/reports/729424

### 77. Stored XSS via Angular Expression Injection (FetLife)
- **Severity**: High
- **Bounty**: Not disclosed
- **Program**: FetLife
- **Platform**: HackerOne
- **Description**: A stored XSS was achieved through Angular expression injection in the subject field when starting conversations with other users. Angular template syntax ({{ }}) was interpreted by the client-side framework.
- **How Found**: Testing input fields with Angular template expressions ({{constructor.constructor('alert(1)')()}}) on Angular-based applications.
- **Impact**: Script execution for FetLife users viewing messages with malicious subjects.
- **Key Takeaway**: Client-side template injection (CSTI) in Angular, Vue, or other frameworks can lead to XSS. Test for {{7*7}} to detect template injection.
- **Source**: https://hackerone.com/reports/1095934

### 78. Persistent XSS via Open Graph Embed on LinkedIn
- **Severity**: High
- **Bounty**: Not disclosed
- **Program**: LinkedIn
- **Platform**: HackerOne
- **Description**: A persistent XSS was found through unvalidated Open Graph embed data on LinkedIn. Shared links with malicious Open Graph metadata could inject scripts when the link preview was rendered.
- **How Found**: Hosting a page with malicious Open Graph meta tags and sharing the URL on LinkedIn to see how the preview was rendered.
- **Impact**: Script execution for LinkedIn users viewing posts with malicious link previews.
- **Key Takeaway**: Link preview/unfurling features that parse Open Graph, Twitter Cards, or oEmbed data are XSS vectors. Control the source page and test what metadata is rendered.
- **Source**: https://hackerone.com/reports/425007

### 79. Stored XSS on LinkedIn App via iframe in Article
- **Severity**: High
- **Bounty**: Not disclosed
- **Program**: LinkedIn
- **Platform**: HackerOne
- **Description**: A stored XSS was achieved through iframe tag injection in LinkedIn articles. The article editor allowed embedding iframes that could execute JavaScript.
- **How Found**: Testing LinkedIn's article editor for HTML tag injection, specifically iframe and embed elements.
- **Impact**: Script execution for all LinkedIn users reading the malicious article.
- **Key Takeaway**: Article/blog editors that support rich HTML embedding are stored XSS targets. Test for iframe, embed, object, and SVG tag injection.
- **Source**: https://hackerone.com/reports/2212950

### 80. Defacement of catalog.data.gov via Cache Poisoning to Stored DOM XSS
- **Severity**: High
- **Bounty**: $750
- **Program**: GSA Bounty
- **Platform**: HackerOne
- **Description**: A government data catalog site was defaced through web cache poisoning that led to stored DOM-based XSS. The poisoned cache served malicious content to all visitors.
- **How Found**: Testing cache behavior on government sites and identifying cacheable endpoints with reflected content that could be stored via cache poisoning.
- **Impact**: Defacement and potential data manipulation on a US government data platform.
- **Key Takeaway**: Government websites often use CDNs and caches that can be poisoned. Cache poisoning to XSS is especially impactful on high-trust government domains.
- **Source**: https://hackerone.com/reports/303730
