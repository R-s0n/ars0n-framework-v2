# Authentication / Authorization Bypass Bug Bounty Reports

> A collection of accepted/disclosed authentication bypass and authorization vulnerability reports from bug bounty programs.

---

### 1. Authentication Bypass via Chaining Username Enumeration + Brute Force (Automattic)
- **Severity:** Critical
- **Vulnerability Type:** Authentication Bypass (Chained Vulnerabilities)
- **Platform:** HackerOne
- **Program:** Automattic
- **Bounty:** $2,000+
- **Description:** An attacker could perform account takeover by chaining username enumeration with login brute force vulnerabilities. The application first revealed valid usernames through differential responses, then lacked rate limiting on login attempts.
- **How It Was Found:** Identifying username enumeration through different error messages for valid vs invalid usernames, then testing rate limiting on the login endpoint.
- **Impact:** Full account takeover of any Automattic user account.
- **Key Takeaway:** Authentication bypass often requires chaining multiple lower-severity issues. Username enumeration + lack of rate limiting + weak password policy = Critical finding.
- **Source:** https://hackerone.com/reports/209008

### 2. Authentication Bypass in Rocket.Chat login-token
- **Severity:** Critical
- **Vulnerability Type:** Authentication Bypass
- **Platform:** HackerOne
- **Program:** Rocket.Chat
- **Bounty:** $2,000+
- **Description:** Improper input data validation in the `login-token` authentication method led to an authentication bypass. The application failed to properly validate the authentication token format, allowing crafted tokens to bypass authentication.
- **How It Was Found:** Testing the login-token parameter with unexpected values, malformed tokens, and injection payloads.
- **Impact:** Full authentication bypass, allowing access to any Rocket.Chat instance without valid credentials.
- **Key Takeaway:** Alternative authentication methods (SSO tokens, magic links, login tokens) often have weaker validation than primary login flows. Test all authentication endpoints, not just the main login form.
- **Source:** https://hackerone.com/reports/1447619

### 3. OAUTH2 Bearer Token Connection Reuse (libcurl - Internet Bug Bounty)
- **Severity:** High
- **Vulnerability Type:** Authentication Bypass via Connection Reuse
- **Platform:** HackerOne
- **Program:** Internet Bug Bounty
- **Bounty:** $2,500+
- **Description:** libcurl might reuse OAUTH2-authenticated connections without properly making sure that the connection was authenticated with the same credentials as set for the current transfer. This meant that requests intended for one OAuth user could be sent on a connection authenticated as a different user.
- **How It Was Found:** Code review of libcurl's connection pooling and reuse logic, focusing on how OAuth2 credentials are tracked across connections.
- **Impact:** Unauthorized access to resources belonging to other OAuth2 users when connection pooling is used.
- **Key Takeaway:** Connection reuse and pooling in HTTP clients can lead to authentication context mixing. Review how libraries handle credential association with pooled connections.
- **Source:** https://hackerone.com/reports/1552110

### 4. Authentication Bypass via Email Verification, OTP, Captcha, and 2FA Bypass (UPchieve)
- **Severity:** Critical
- **Vulnerability Type:** Multiple Authentication Bypass
- **Platform:** HackerOne
- **Program:** UPchieve
- **Bounty:** $500+
- **Description:** Attackers could bypass multiple authentication control mechanisms including email verification, OTP verification, Captcha validation, and 2FA challenges. The application had weaknesses in each verification layer.
- **How It Was Found:** Systematic testing of each authentication layer: manipulating email verification links, brute-forcing OTPs, bypassing Captcha, and testing 2FA implementation.
- **Impact:** Complete bypass of all authentication protections, allowing unauthorized account access.
- **Key Takeaway:** Test every layer of authentication independently. Just because 2FA exists doesn't mean it's properly enforced. Check for: direct API access bypassing 2FA, session fixation after partial auth, and OTP brute-force without lockout.
- **Source:** https://hackerone.com/reports/1406471

### 5. Authentication Bypass by Spoofing in Revive Adserver
- **Severity:** Critical
- **Vulnerability Type:** Authentication Bypass via Spoofing
- **Platform:** HackerOne
- **Program:** Revive Adserver
- **Bounty:** $500+
- **Description:** An authentication bypass affecting all versions of Revive Adserver including the latest release. The vulnerability allowed attackers to spoof authentication credentials and gain unauthorized access to the ad serving platform.
- **How It Was Found:** Analyzing the authentication mechanism for spoofing vectors, testing with manipulated authentication headers and tokens.
- **Impact:** Complete administrative access to ad serving infrastructure.
- **Key Takeaway:** Ad serving platforms and content management systems often have authentication vulnerabilities that affect all versions. Review open-source authentication code for logical flaws.
- **Source:** https://hackerone.com/reports/576504

### 6. Sign in with Apple ID - 2FA Bypass (Cloudflare)
- **Severity:** High
- **Vulnerability Type:** 2FA Bypass
- **Platform:** HackerOne
- **Program:** Cloudflare
- **Bounty:** $3,000+
- **Description:** It was possible to bypass configured Cloudflare 2FA when logging in using the Apple ID authentication flow. The SSO/social login flow did not enforce the same 2FA requirements as direct login.
- **How It Was Found:** Testing different login methods (direct login vs social login/SSO) and comparing 2FA enforcement between them.
- **Impact:** 2FA bypass for Cloudflare accounts, undermining the security of the additional authentication factor.
- **Key Takeaway:** When an application supports multiple login methods (password, SSO, social login, magic links), test 2FA enforcement for EACH method. SSO and social login often bypass 2FA.
- **Source:** https://hackerone.com/reports/1593404

### 7. Broken Authentication and Session Management (Phabricator)
- **Severity:** High
- **Vulnerability Type:** Broken Authentication
- **Platform:** HackerOne
- **Program:** Phabricator
- **Bounty:** $500+
- **Description:** Broken authentication and session management vulnerabilities in Phabricator allowed attackers to compromise sessions, credentials, or keys to assume other users' identities.
- **How It Was Found:** Analyzing session management: token generation, session fixation, session timeout, and cookie security attributes.
- **Impact:** Session hijacking and identity impersonation on the code collaboration platform.
- **Key Takeaway:** Session management is as important as authentication. Test for: predictable session tokens, session fixation, missing secure/httponly flags, and sessions that don't invalidate on password change.
- **Source:** https://hackerone.com/reports/17474

### 8. Critical Authentication Bypass via Attacker's MFA Code
- **Severity:** Critical
- **Vulnerability Type:** MFA Bypass
- **Platform:** Private Program
- **Program:** Undisclosed (public bounty program)
- **Bounty:** Significant
- **Description:** A critical authentication bypass where an attacker could use their own MFA code to authenticate as another user. The MFA verification was not properly tied to the user being authenticated, allowing cross-user MFA validation.
- **How It Was Found:** Testing MFA verification by submitting MFA codes generated for Account A while authenticating as Account B.
- **Impact:** Complete account takeover by bypassing MFA with the attacker's own codes.
- **Key Takeaway:** Test if MFA codes are properly bound to the authenticating user. Try using one account's MFA code to verify another account. Also test: MFA code reuse, MFA backup codes, and MFA enrollment bypass.
- **Source:** https://medium.com/@sharp488/critical-authentication-bypass-account-takeover-via-attackers-mfa-code-fadf36fe6e34

### 9. Two-Factor Authentication Bypass on Instagram/Facebook (Meta)
- **Severity:** Critical
- **Vulnerability Type:** 2FA Bypass
- **Platform:** Meta Bug Bounty
- **Program:** Meta (Facebook/Instagram)
- **Bounty:** $27,000
- **Description:** A security researcher discovered a two-factor authentication bypass vulnerability affecting both Instagram and Facebook. The bypass allowed access to accounts protected by 2FA without providing the correct second factor.
- **How It Was Found:** Testing the 2FA verification flow for race conditions, endpoint manipulation, and session state inconsistencies.
- **Impact:** Account takeover of any Instagram or Facebook account protected by 2FA.
- **Key Takeaway:** Meta's bug bounty program pays premium bounties for 2FA bypass. Test for: race conditions in 2FA verification, session manipulation between 2FA challenge and verification, and backup code enumeration.
- **Source:** https://www.bitdefender.com/en-us/blog/hotforsecurity/meta-pays-out-bounties-for-account-takeover-and-two-factor-authentication-bypass-exploits

### 10. Account Takeover via Canvas Apps Cross-Window-Message (Meta)
- **Severity:** Critical
- **Vulnerability Type:** Authentication Bypass via Cross-Window-Message
- **Platform:** Meta Bug Bounty
- **Program:** Meta
- **Bounty:** $62,500
- **Description:** An account takeover vulnerability in Canvas Apps served in Comet was found due to failure in Cross-Window-Message Origin validation. The application did not properly validate the origin of messages received through the postMessage API.
- **How It Was Found:** Analyzing the postMessage communication between the main application and Canvas Apps, identifying missing origin validation.
- **Impact:** Full Facebook account takeover through a malicious Canvas application.
- **Key Takeaway:** postMessage vulnerabilities are increasingly valuable. Test all window.addEventListener('message') handlers for missing or weak origin validation. Tools like PMBF (PostMessage Bug Finder) can automate detection.
- **Source:** Referenced in Meta bug bounty disclosures

### 11. Race Conditions in OAuth 2 API Implementations
- **Severity:** High
- **Vulnerability Type:** Authentication Bypass via Race Condition
- **Platform:** HackerOne
- **Program:** Internet Bug Bounty
- **Bounty:** $2,500+
- **Description:** Most OAuth 2 API implementations had race condition vulnerabilities allowing a malicious application to obtain multiple access_token and refresh_token pairs while only one pair should be generated per authorization code exchange.
- **How It Was Found:** Sending multiple concurrent token exchange requests with the same authorization code, observing that multiple valid token pairs were issued.
- **Impact:** Token accumulation allowing persistent access even after token revocation.
- **Key Takeaway:** OAuth 2 token exchange endpoints should be tested for race conditions. Use Turbo Intruder or custom concurrent request scripts to test for token duplication.
- **Source:** https://hackerone.com/reports/55140

### 12. Password Change Without Current Password Verification (UPchieve)
- **Severity:** High
- **Vulnerability Type:** Broken Authentication
- **Platform:** HackerOne
- **Program:** UPchieve
- **Bounty:** $500+
- **Description:** A business logic error where the password change functionality did not require verification of the current password. An attacker who gained temporary access to a session could permanently take over the account.
- **How It Was Found:** Testing the password change endpoint to see if the current/old password was required and properly validated.
- **Impact:** Account takeover through session hijacking or CSRF on the password change endpoint.
- **Key Takeaway:** Always check if sensitive account actions (password change, email change, 2FA disable) require re-authentication. Many applications skip current password verification.
- **Source:** https://hackerone.com/reports/1296597

### 13. JWT Token Manipulation - Algorithm Confusion
- **Severity:** Critical
- **Vulnerability Type:** Authentication Bypass via JWT
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $2,000-$10,000
- **Description:** JWT (JSON Web Token) authentication can be bypassed through algorithm confusion attacks: changing RS256 to HS256 (using the public key as the HMAC secret), setting algorithm to "none", or using weak signing keys.
- **How It Was Found:** Analyzing JWT tokens (jwt.io), testing algorithm switching, testing with "none" algorithm, and brute-forcing weak signing keys using jwt_tool or hashcat.
- **Impact:** Complete authentication bypass, ability to forge valid tokens for any user including admin accounts.
- **Key Takeaway:** Always test JWT implementations for: algorithm confusion (RS256->HS256), none algorithm, weak signing keys, key ID (kid) injection, missing expiration validation, and token reuse after logout.
- **Source:** Multiple bug bounty reports and writeup collections

### 14. Password Reset Poisoning
- **Severity:** High
- **Vulnerability Type:** Account Takeover via Password Reset
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $1,000-$5,000
- **Description:** Password reset poisoning occurs when an attacker manipulates the Host header or other headers during a password reset request, causing the password reset link to point to an attacker-controlled domain. When the victim clicks the link, the reset token is sent to the attacker.
- **How It Was Found:** Manipulating the Host header, X-Forwarded-Host, or Origin header in password reset requests to point to an attacker-controlled domain.
- **Impact:** Account takeover through stolen password reset tokens.
- **Key Takeaway:** Test password reset flows with modified Host, X-Forwarded-Host, and Referer headers. If the reset link URL changes based on these headers, you've found password reset poisoning.
- **Source:** Multiple bug bounty reports

### 15. OAuth Redirect URI Manipulation
- **Severity:** High
- **Vulnerability Type:** Authorization Bypass / Account Takeover
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $2,000-$10,000
- **Description:** OAuth implementations often have vulnerabilities in redirect_uri validation, allowing attackers to steal authorization codes or access tokens. Common issues include: open redirects in redirect_uri, path traversal in redirect_uri, and subdomain matching bypass.
- **How It Was Found:** Testing redirect_uri parameter with: different paths (/callback/../evil), subdomain variations (evil.example.com), URL encoding, and open redirect chains.
- **Impact:** OAuth token theft leading to account takeover on the affected platform.
- **Key Takeaway:** OAuth redirect_uri validation is a goldmine. Test for: partial path matching, subdomain wildcards, URL encoding bypass, fragment injection, and chaining with open redirects. Use tools like oauthscan for automated testing.
- **Source:** Multiple bug bounty reports and OAuth security research

### 16. Session Fixation Attacks
- **Severity:** High
- **Vulnerability Type:** Session Fixation
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $500-$3,000
- **Description:** Session fixation occurs when the application does not regenerate the session ID after authentication. An attacker sets a known session ID before the victim authenticates, and after authentication, the attacker uses the same session ID to access the victim's account.
- **How It Was Found:** Testing if the session cookie changes after login. If the pre-authentication and post-authentication session IDs are the same, session fixation is possible.
- **Impact:** Account takeover by using a pre-set session ID after victim authentication.
- **Key Takeaway:** Always verify that applications regenerate session tokens after authentication, privilege elevation, and password change. Session fixation is simple to test but often overlooked.
- **Source:** Multiple bug bounty reports

### 17. API Key Authentication Bypass
- **Severity:** High
- **Vulnerability Type:** Authentication Bypass
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $1,000-$5,000
- **Description:** API endpoints that rely solely on API keys for authentication can often be bypassed through: exposed API keys in client-side code, API keys in public repositories, lack of per-endpoint authorization after key validation, or API key brute-force.
- **How It Was Found:** Reviewing JavaScript source code, GitHub searches, and testing API endpoints with leaked or guessed API keys.
- **Impact:** Unauthorized API access, potential data extraction and manipulation.
- **Key Takeaway:** Search for API keys in: JavaScript files, mobile app packages, GitHub repos (using dorks like "api_key" or "client_secret"), and public Postman collections.
- **Source:** Multiple bug bounty reports

### 18. SAML Authentication Bypass
- **Severity:** Critical
- **Vulnerability Type:** SAML Authentication Bypass
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $5,000-$20,000
- **Description:** SAML-based SSO implementations can be bypassed through: XML signature wrapping attacks, comment injection in NameID, SAML response manipulation, and replay attacks.
- **How It Was Found:** Intercepting and manipulating SAML responses using Burp Suite with SAML Raider extension, testing for signature validation bypass and response manipulation.
- **Impact:** Authentication bypass on any application using SAML SSO, potential access to all SSO-connected applications.
- **Key Takeaway:** SAML implementations are complex and frequently vulnerable. Use Burp SAML Raider to test for: comment injection (admin<!-- -->@attacker.com), signature exclusion, certificate faking, and response replay.
- **Source:** Multiple bug bounty reports and SAML security research

### 19. GraphQL Authentication Bypass
- **Severity:** High
- **Vulnerability Type:** Authorization Bypass
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $2,000-$10,000
- **Description:** GraphQL APIs often have authorization issues where: introspection reveals hidden queries, batch queries bypass rate limiting, nested queries bypass authorization checks, and mutations lack proper authentication.
- **How It Was Found:** Using GraphQL introspection to discover hidden endpoints, testing all queries and mutations with different authentication levels, and using tools like InQL or graphql-cop.
- **Impact:** Unauthorized access to data and operations through GraphQL API.
- **Key Takeaway:** GraphQL APIs deserve thorough authorization testing. Test every query and mutation: unauthenticated, with low-privilege tokens, and with manipulated variables. Use InQL for introspection and endpoint discovery.
- **Source:** Multiple bug bounty reports

### 20. Account Takeover via Phone Number Recycling
- **Severity:** High
- **Vulnerability Type:** Account Takeover
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $1,000-$5,000
- **Description:** Applications using phone numbers for authentication/recovery are vulnerable to account takeover when phone numbers are recycled by carriers. A new phone number owner can receive OTPs meant for the previous owner.
- **How It Was Found:** Identifying applications that use phone-based authentication and testing the account recovery flow with phone number ownership verification.
- **Impact:** Account takeover for accounts linked to recycled phone numbers.
- **Key Takeaway:** Report applications that rely solely on phone numbers for authentication/recovery without additional verification. This is a systemic issue that affects many services.
- **Source:** Multiple security research and bug bounty reports

---

## Authentication Bypass Hunting Methodology Summary

### Tools Commonly Used
- **Burp Suite** - Request manipulation and authentication testing
- **SAML Raider (Burp Extension)** - SAML authentication testing
- **jwt_tool** - JWT token manipulation and testing
- **Turbo Intruder** - Race condition testing in auth flows
- **Autorize (Burp Extension)** - Automated authorization testing
- **graphql-cop / InQL** - GraphQL authorization testing

### Common Authentication Bypass Vectors
1. 2FA/MFA bypass (multiple login methods, race conditions)
2. JWT manipulation (algorithm confusion, none algorithm)
3. OAuth redirect_uri manipulation
4. SAML response manipulation
5. Password reset poisoning
6. Session fixation
7. API key exposure
8. Rate limiting bypass for brute force
9. postMessage origin validation bypass
10. Social login flow inconsistencies

---

## Additional Reports (Expanded Collection)

### 21. Account Takeover via Authentication Bypass in TikTok Account Recovery
- **Severity**: Critical
- **Bounty**: $12,000
- **Program**: TikTok
- **Platform**: HackerOne
- **Description**: An improper authentication mechanism in TikTok's account recovery process could be used for account takeovers on Android devices. The recovery flow did not properly validate the identity of the user initiating account recovery.
- **How Found**: Testing the account recovery flow on the Android app, analyzing how the recovery verification was handled and finding that authentication steps could be bypassed.
- **Impact**: Full account takeover of any TikTok account through the recovery process without knowing the victim's credentials.
- **Key Takeaway**: Mobile app account recovery flows often have different (weaker) implementations than web flows. Test recovery mechanisms on all platforms separately.
- **Source**: https://hackerone.com/reports/2443228

### 22. Bypass Two-Factor Authentication in TikTok Login Flow
- **Severity**: High
- **Bounty**: $5,000+
- **Program**: TikTok
- **Platform**: HackerOne
- **Description**: A vulnerability allowed bypassing two-factor authentication during the TikTok login flow, enabling access to 2FA-protected accounts without providing the second authentication factor.
- **How Found**: Analyzing the login flow to find ways to skip or bypass the 2FA challenge step while still obtaining a valid session.
- **Impact**: Bypass of 2FA protection on TikTok accounts, undermining the security of accounts that had enabled two-factor authentication.
- **Key Takeaway**: Test if 2FA can be bypassed by manipulating the login flow sequence, skipping verification steps, or accessing endpoints that grant sessions without 2FA verification.
- **Source**: https://hackerone.com/reports/1747978

### 23. Authentication Bypass in Subscription Management Endpoint (lemlist)
- **Severity**: High
- **Bounty**: $500+
- **Program**: lemlist
- **Platform**: HackerOne
- **Description**: A vulnerability in the subscription management functionality allowed unauthorized access to customer billing information due to insufficient authentication and authorization controls on an API endpoint.
- **How Found**: Testing subscription management API endpoints without proper authentication tokens and discovering that billing data was accessible.
- **Impact**: Unauthorized access to customer billing information, subscription details, and payment data.
- **Key Takeaway**: Billing and subscription management endpoints are frequently overlooked during security testing. They often have weaker authentication requirements than core features.
- **Source**: https://hackerone.com/reports/3417162

### 24. Jitsi-Meet Authentication Bypass via JWT Symmetric Algorithm (8x8)
- **Severity**: High
- **Bounty**: $1,000+
- **Program**: 8x8
- **Platform**: HackerOne
- **Description**: A Prosody module in Jitsi-Meet allowed the use of symmetrical algorithms to validate JWTs, meaning tokens generated by arbitrary sources could be used to gain authorization to protected meeting rooms.
- **How Found**: Analyzing the JWT validation logic in the Prosody module and discovering that symmetric algorithms (like HS256) were accepted, allowing anyone with knowledge of the shared secret to forge valid tokens.
- **Impact**: Unauthorized access to any protected Jitsi meeting room by forging valid JWT tokens.
- **Key Takeaway**: JWT implementations that accept both symmetric and asymmetric algorithms are vulnerable to algorithm confusion attacks. Verify that the server strictly enforces the expected algorithm.
- **Source**: https://hackerone.com/reports/1210502

### 25. 2FA Requirement Bypass When Inviting New Members (Omise)
- **Severity**: Medium
- **Bounty**: $500+
- **Program**: Omise
- **Platform**: HackerOne
- **Description**: A 2FA restriction could be bypassed by modifying client-side responses (match and replace from false to true), allowing invitations to be sent to new team members without the inviting user having 2FA enabled.
- **How Found**: Using Burp Suite's Match and Replace feature to change the 2FA enforcement response from "false" to "true" in the client-side validation.
- **Impact**: Bypass of organizational security policy requiring 2FA before performing sensitive operations like inviting new team members.
- **Key Takeaway**: Client-side enforcement of 2FA is never sufficient. Use Burp's Match and Replace to flip boolean values in responses to test if security checks are client-side only.
- **Source**: https://hackerone.com/reports/3356149

### 26. Session Replay Attack Allows Authentication Bypass
- **Severity**: Critical
- **Bounty**: $1,000+
- **Program**: Undisclosed
- **Platform**: HackerOne
- **Description**: An attacker could bypass authentication by capturing a valid login response (including session cookies and tokens) and replaying it during a failed login attempt with incorrect credentials, receiving a valid session.
- **How Found**: Capturing successful login responses and replaying them after failed authentication attempts, discovering the server accepted the replayed session data.
- **Impact**: Authentication bypass allowing access to any account by replaying a previously captured valid authentication response.
- **Key Takeaway**: Test for session replay attacks by capturing valid auth responses and injecting them into failed login attempts. Server-side session validation should be tied to the specific request context.
- **Source**: https://hackerone.com/reports/3120790

### 27. Account Takeover via Email ID Change and Forgot Password (New Relic)
- **Severity**: Critical
- **Bounty**: $2,048
- **Program**: New Relic
- **Platform**: HackerOne
- **Description**: An attacker could take over any New Relic account by exploiting a vulnerability in the email change functionality combined with the forgot password feature. The email change did not require proper re-authentication.
- **How Found**: Testing the email change flow for re-authentication requirements and chaining it with the password reset functionality.
- **Impact**: Full account takeover of any New Relic user account by changing the account email and then resetting the password.
- **Key Takeaway**: Email change + password reset is a classic account takeover chain. Always test if changing the account email requires the current password or additional verification.
- **Source**: Referenced in HackerOne top account takeover reports (214 upvotes)

### 28. Account Takeover Due to Misconfiguration (Mattermost)
- **Severity**: High
- **Bounty**: $150
- **Program**: Mattermost
- **Platform**: HackerOne
- **Description**: A misconfiguration in Mattermost's authentication setup allowed account takeover. The vulnerability stemmed from improper security configuration that could be exploited by an attacker to gain unauthorized access.
- **How Found**: Analyzing Mattermost's authentication configuration for common misconfigurations and testing edge cases in the login flow.
- **Impact**: Account takeover of Mattermost users on affected instances.
- **Key Takeaway**: Open-source collaboration platforms often have complex configuration options. Test default and common configurations for authentication weaknesses.
- **Source**: https://hackerone.com/reports/1114347

### 29. 0-Click Account Takeover via Password Reset (Remitly)
- **Severity**: Critical
- **Bounty**: $5,000+
- **Program**: Remitly
- **Platform**: HackerOne
- **Description**: A critical 0-click vulnerability in the password reset functionality at the /orchestrator/v1/password_reset/start endpoint allowed an attacker to reset any victim's password without any interaction or consent from the victim.
- **How Found**: Analyzing the password reset API endpoint and discovering that it did not properly validate the requester's identity or require victim interaction to complete the reset.
- **Impact**: Complete account takeover of any Remitly user without any victim interaction, affecting a financial remittance service handling money transfers.
- **Key Takeaway**: 0-click vulnerabilities in password reset are among the most critical findings. Test if password reset flows can be completed entirely by the attacker without any victim action (clicking links, entering codes).
- **Source**: https://hackerone.com/reports/2831902

### 30. 0-Click Account Takeover via Timed Race Condition (Mars)
- **Severity**: Critical
- **Bounty**: Recognized (no monetary bounty)
- **Program**: Mars
- **Platform**: HackerOne
- **Description**: An account takeover vulnerability in the forgot password functionality where an attacker could send carefully timed requests using a single-packet attack to compromise accounts through a race condition.
- **How Found**: Using single-packet attack techniques to send concurrent requests to the forgot-password endpoint, exploiting a race condition window in the password reset token generation.
- **Impact**: Full account takeover of Mars platform users through exploiting timing vulnerabilities in the password reset flow.
- **Key Takeaway**: Race conditions in authentication flows are underreported. Use single-packet attacks (HTTP/2 request smuggling or TCP packet batching) for precise timing exploitation.
- **Source**: https://hackerone.com/reports/2142109

### 31. Account Takeover in Password Reset Flow (Mars)
- **Severity**: Critical
- **Bounty**: Recognized (no monetary bounty)
- **Program**: Mars
- **Platform**: HackerOne
- **Description**: A separate vulnerability in the Mars password reset flow allowed account takeover through improper validation of password reset tokens or insufficient binding of reset tokens to specific user accounts.
- **How Found**: Testing password reset token validation for weaknesses including token prediction, token reuse, and cross-user token acceptance.
- **Impact**: Full account takeover through the password reset mechanism.
- **Key Takeaway**: Password reset flows deserve multiple rounds of testing. Check for token predictability, token expiration, token reuse after password change, and token binding to specific users.
- **Source**: https://hackerone.com/reports/3228888

### 32. 1-Click Account Takeover via Auth Token Theft (Hostinger)
- **Severity**: Critical
- **Bounty**: Recognized (no monetary bounty)
- **Program**: Hostinger
- **Platform**: HackerOne
- **Description**: A 1-click account takeover via auth token theft on marketing.hostinger.com. Since this subdomain is part of hostinger.com and is whitelisted for redirects, an attacker could exploit it to steal users' auth tokens and gain full account access.
- **How Found**: Discovering that the marketing subdomain was whitelisted for redirects, then finding a way to exfiltrate auth tokens through the trusted subdomain.
- **Impact**: Full account takeover of any Hostinger user with a single click, giving access to web hosting, domains, and all hosted services.
- **Key Takeaway**: Whitelisted subdomains for redirects can be attack vectors. If any subdomain in the whitelist has vulnerabilities, it can be used to steal tokens from the parent domain.
- **Source**: https://hackerone.com/reports/3081691

### 33. Account Takeover via Insecure Zendesk SSO Implementation (Trint)
- **Severity**: Critical
- **Bounty**: $500+
- **Program**: Trint Ltd
- **Platform**: HackerOne
- **Description**: An insecure Zendesk SSO implementation allowed authentication bypass and account takeover. The SSO integration between Trint and Zendesk did not properly validate authentication assertions.
- **How Found**: Analyzing the SSO flow between Trint and Zendesk for authentication validation weaknesses, finding that the SSO handshake could be manipulated.
- **Impact**: Account takeover through the Zendesk support portal SSO integration.
- **Key Takeaway**: Third-party SSO integrations (Zendesk, Salesforce, etc.) are frequently misconfigured. Test the SSO handshake between the main application and integrated services.
- **Source**: https://hackerone.com/reports/638635

### 34. Account Takeover via JWT Signature Bypass (Linktree)
- **Severity**: Critical
- **Bounty**: Recognized (no monetary bounty)
- **Program**: Linktree
- **Platform**: HackerOne
- **Description**: Backend services did not properly validate JWTs, and JWT validation could be bypassed by setting the expiration date claim to a unix timestamp in the past, enabling account takeover.
- **How Found**: Analyzing JWT token structure and testing with manipulated claims, discovering that expired tokens with past timestamps were accepted instead of rejected.
- **Impact**: Complete authentication bypass and account takeover for any Linktree user by forging JWT tokens with manipulated expiration claims.
- **Key Takeaway**: JWT expiration validation bugs are common. Test with: expired tokens, tokens with past dates, tokens with far-future dates, and tokens with missing exp claims.
- **Source**: https://hackerone.com/reports/1760403

### 35. Hacker Can Bypass 2FA Requirement and Invite Collaborators (HackerOne)
- **Severity**: Medium
- **Bounty**: $500+
- **Program**: HackerOne
- **Platform**: HackerOne
- **Description**: A vulnerability allowed hackers to bypass the 2FA requirement when inviting collaborators to their HackerOne reports, circumventing a security control meant to prevent unauthorized additions to sensitive vulnerability reports.
- **How Found**: Testing the collaborator invitation flow to see if the 2FA enforcement could be bypassed through API manipulation or workflow exploitation.
- **Impact**: Bypass of 2FA security requirement, potentially allowing unauthorized collaborator additions to sensitive vulnerability reports.
- **Key Takeaway**: 2FA enforcement should be tested for every sensitive action, not just login. Check if 2FA is enforced for: invitations, permission changes, settings modifications, and data exports.
- **Source**: https://hackerone.com/reports/418767

### 36. SAML Authentication Bypass in Rocket.Chat
- **Severity**: Critical
- **Bounty**: $2,000+
- **Program**: Rocket.Chat
- **Platform**: HackerOne
- **Description**: A SAML authentication bypass in Rocket.Chat allowed attackers to bypass the SAML-based SSO authentication mechanism and gain unauthorized access to the chat platform.
- **How Found**: Intercepting and manipulating SAML responses using Burp Suite with SAML Raider extension, testing for signature validation bypass and response manipulation.
- **Impact**: Full authentication bypass on Rocket.Chat instances using SAML SSO, potentially accessing all chat messages and channels.
- **Key Takeaway**: SAML implementations in chat platforms are high-value targets. Use SAML Raider to test for: signature removal, signature wrapping, certificate substitution, and assertion replay.
- **Source**: https://hackerone.com/reports/812064

### 37. HackerOne SAML Signup Domain Bypass
- **Severity**: High
- **Bounty**: $2,500+
- **Program**: HackerOne
- **Platform**: HackerOne
- **Description**: A SAML signup domain restriction could be bypassed on HackerOne's platform, allowing users from unauthorized domains to create accounts or access programs restricted to specific SAML domains.
- **How Found**: Testing SAML response manipulation to change domain claims and bypass domain-based access restrictions.
- **Impact**: Unauthorized access to HackerOne programs restricted to specific organizations through domain-based SAML authentication.
- **Key Takeaway**: Domain-based restrictions in SAML are often bypassable through claim manipulation. Test if you can modify the email domain in SAML assertions while maintaining a valid signature.
- **Source**: https://hackerone.com/reports/2101076

### 38. GitHub Enterprise SAML Authentication Bypass (CVE-2024-4985)
- **Severity**: Critical
- **Bounty**: $20,000+ (estimated)
- **Program**: GitHub
- **Platform**: GitHub Security Bug Bounty
- **Description**: A critical authentication bypass in GitHub Enterprise Server affected installations using SAML SSO with optional encrypted assertions enabled. Attackers could forge SAML responses to provision and gain access to user accounts with site administrator privileges.
- **How Found**: Security research into SAML encrypted assertions handling, discovering that the decryption and validation logic could be exploited to forge valid assertions.
- **Impact**: Complete administrative access to any GitHub Enterprise Server instance using SAML SSO with encrypted assertions.
- **Key Takeaway**: SAML encrypted assertions add complexity that can introduce new attack surfaces. Test SAML implementations with encrypted assertions enabled for different bypass techniques than unencrypted flows.
- **Source**: https://projectdiscovery.io/blog/github-enterprise-saml-authentication-bypass

### 39. Ruby-SAML Authentication Bypass via Parser Differentials (CVE-2024-45409)
- **Severity**: Critical
- **Bounty**: $10,000+ (GitHub Bug Bounty engagement)
- **Program**: GitHub (ruby-saml library)
- **Platform**: Private Bug Bounty Engagement
- **Description**: A critical vulnerability in the ruby-saml library exploited parser differentials between REXML and Nokogiri XML parsers during signature verification. An attacker with a single valid signature could construct SAML assertions for any user.
- **How Found**: Through a private bug bounty engagement where researchers discovered that ruby-saml used two different XML parsers (REXML and Nokogiri) during signature verification, creating exploitable inconsistencies.
- **Impact**: Authentication bypass on any application using ruby-saml for SAML SSO, including GitHub Enterprise. One valid signature could forge assertions for any user.
- **Key Takeaway**: XML parser differentials in SAML libraries are a cutting-edge attack vector. Different parsers may handle XML canonicalization, comments, and whitespace differently, creating exploitable gaps.
- **Source**: https://github.blog/security/sign-in-as-anyone-bypassing-saml-sso-authentication-with-parser-differentials/

### 40. OAuth Vulnerabilities - Exploiting Redirect URI for Account Takeover
- **Severity**: High
- **Bounty**: $5,000+
- **Program**: Multiple programs
- **Platform**: Various
- **Description**: Multiple OAuth implementations were found vulnerable to redirect_uri manipulation, where attackers could steal authorization codes or access tokens by redirecting the OAuth callback to attacker-controlled domains through path traversal or open redirect chains.
- **How Found**: Testing redirect_uri parameter with path traversal (/../evil), subdomain variations, URL encoding, and chaining with existing open redirect vulnerabilities.
- **Impact**: OAuth token theft leading to account takeover on the affected platforms.
- **Key Takeaway**: OAuth redirect_uri bypasses are a rich attack surface. Test: partial path matching, adding paths after the allowed URI, fragment injection, URL encoding, and chaining with open redirects on allowed domains.
- **Source**: https://blog.doyensec.com/2025/01/30/oauth-common-vulnerabilities.html

### 41. Breaking the Chain - Exploiting OAuth and Forgot Password for Account Takeover
- **Severity**: Critical
- **Bounty**: $5,000+
- **Program**: Undisclosed
- **Platform**: Bugcrowd
- **Description**: An account takeover was achieved by exploiting weaknesses in the OAuth implementation combined with the forgot password flow. The OAuth flow leaked user information that could be used to bypass the password reset verification.
- **How Found**: Chaining an OAuth information leak with the forgot password functionality, using data obtained from the OAuth flow to complete the password reset without proper authorization.
- **Impact**: Full account takeover by combining OAuth weaknesses with password reset vulnerabilities.
- **Key Takeaway**: Chaining OAuth flaws with other authentication weaknesses multiplies impact. Look for data leaked in OAuth flows (user IDs, emails, tokens) that can be used in other attack vectors.
- **Source**: https://www.bugcrowd.com/blog/breaking-the-chain-exploiting-oauth-and-forgot-password-for-account-takeover/

### 42. JWT Audience Claim Not Properly Validated (Internet Bug Bounty)
- **Severity**: Medium
- **Bounty**: $1,000+
- **Program**: Internet Bug Bounty
- **Platform**: HackerOne
- **Description**: JWT audience claim validation was improperly implemented, allowing tokens intended for one service to be used against another service. The audience (aud) claim was not verified before granting access.
- **How Found**: Testing JWT tokens across different services and discovering that tokens issued for one service were accepted by other services sharing the same signing key.
- **Impact**: Cross-service authentication bypass where a JWT valid for one service could grant access to a different service.
- **Key Takeaway**: JWT audience (aud) claim validation is frequently missing. Test if tokens from one microservice/subdomain are accepted by other services in the same ecosystem.
- **Source**: https://hackerone.com/reports/1889161

### 43. Grafana JWT URL-Login Token Leak to Data Sources
- **Severity**: High
- **Bounty**: $5,000+
- **Program**: Grafana
- **Platform**: GitHub Bug Bounty
- **Description**: When using URL LOGIN on a data-source endpoint, Grafana's auth_token parameter was not removed in proxied requests but instead passed to the target data source. This leaked user authentication tokens to third-party services.
- **How Found**: Analyzing how Grafana proxied requests to data sources and discovering that authentication tokens from URL-based login were forwarded to external data source endpoints.
- **Impact**: Full access to Grafana as the victim user if the third-party data source captured the leaked auth token.
- **Key Takeaway**: Proxy and data source integration points frequently leak authentication tokens. Test if auth headers/parameters are stripped when requests are forwarded to external services.
- **Source**: https://github.com/grafana/bugbounty/security/advisories/GHSA-5585-m9r5-p86j

### 44. $12,000 2FA Bypass via Rate Limit Bypass and OTP Brute Force
- **Severity**: Critical
- **Bounty**: $12,000
- **Program**: Undisclosed
- **Platform**: Private Program
- **Description**: A researcher bypassed 2FA by circumventing rate limits to brute force the one-time password (OTP) code. The application had rate limiting on the 2FA verification endpoint, but the rate limit could be bypassed through request manipulation.
- **How Found**: Testing the 2FA OTP verification endpoint for rate limiting, then finding bypass techniques (IP rotation, header manipulation, endpoint variations) to brute force the 6-digit OTP.
- **Impact**: Complete 2FA bypass through OTP brute force, rendering two-factor authentication ineffective.
- **Key Takeaway**: Rate limiting on 2FA endpoints must be robust. Test for rate limit bypasses via: X-Forwarded-For header rotation, API version differences, case variations in endpoints, and adding extra parameters.
- **Source**: https://medium.com/@rahulgairola/the-12-000-2fa-bypass-so-simple-yet-so-critical-e3f7d7e5751c

### 45. 2FA Bypass - Non-Expiring Confirmation Tokens (GSA Bounty)
- **Severity**: High
- **Bounty**: N/A (Government VDP)
- **Program**: GSA Bounty
- **Platform**: HackerOne
- **Description**: Two-factor authentication could be bypassed because confirmation tokens did not expire. Once a valid 2FA token was generated, it could be reused indefinitely, even after the session that generated it was terminated.
- **How Found**: Testing token expiration by saving 2FA confirmation tokens and attempting to reuse them after various time intervals and session changes.
- **Impact**: Persistent 2FA bypass by reusing old, non-expiring confirmation tokens.
- **Key Takeaway**: 2FA tokens must have strict expiration. Test for: token reuse after use, token validity after password change, token validity after session termination, and token validity across different sessions.
- **Source**: https://hackerone.com/reports/264090

### 46. Authentication Bypass Leads to Information Disclosure (Slack)
- **Severity**: High
- **Bounty**: $1,000+
- **Program**: Slack
- **Platform**: HackerOne
- **Description**: A security researcher discovered an information disclosure on Slack's server which took advantage of an authorization error that allowed viewing sensitive information that should have been restricted to authenticated and authorized users.
- **How Found**: Testing Slack's API endpoints and server responses for authorization inconsistencies that allowed access to sensitive data without proper authentication.
- **Impact**: Disclosure of sensitive Slack server information to unauthorized users.
- **Key Takeaway**: Even well-secured platforms like Slack can have authorization gaps. Focus on edge cases and less commonly accessed endpoints that may have been overlooked.
- **Source**: https://hackerone.com/reports/129918

### 47. Bypass Invite Accept for Victim - Force User into Workspace (Slack)
- **Severity**: High
- **Bounty**: $1,000+
- **Program**: Slack
- **Platform**: HackerOne
- **Description**: Slack administrators were able to add arbitrary users (identified by email address) to their Workspace without the user accepting the invitation, bypassing the access control requiring recipient consent.
- **How Found**: Testing the workspace invitation flow and discovering that the invitation acceptance step could be bypassed, automatically adding users to workspaces.
- **Impact**: Users could be forcibly added to Slack workspaces without their consent, potentially exposing them to malicious content or phishing.
- **Key Takeaway**: Invitation and consent flows should be tested for bypass. Check if the acceptance step can be skipped through direct API calls or by manipulating the invitation state.
- **Source**: https://hackerone.com/reports/1663361

### 48. Race Condition Authentication Bypass Leads to Full Account Takeover
- **Severity**: Critical
- **Bounty**: $5,000+
- **Program**: Undisclosed (large e-commerce)
- **Platform**: Private Program
- **Description**: A race condition in the OTP-based login flow of a large e-commerce company allowed authentication as any user solely by knowing their email address. The race condition occurred during OTP validation, allowing concurrent requests to bypass verification.
- **How Found**: Sending multiple concurrent OTP validation requests using single-packet attack techniques, exploiting the race window in the authentication state machine.
- **Impact**: Full account takeover of any user account using only their email address, no password or OTP knowledge required.
- **Key Takeaway**: OTP verification endpoints are prime targets for race condition attacks. Use HTTP/2 single-packet attacks or Turbo Intruder for precise concurrent request delivery to authentication endpoints.
- **Source**: https://medium.com/@keizobugbounty/race-condition-authentication-bypass-leads-to-full-account-takeover-6b5c9bc0a54d

### 49. Unauthorized Password Reset Allows Account Takeover (lemlist)
- **Severity**: Critical
- **Bounty**: $500+
- **Program**: lemlist
- **Platform**: HackerOne
- **Description**: An unauthorized password reset vulnerability in lemlist allowed an attacker to reset any user's password without proper authorization, leading to full account takeover.
- **How Found**: Analyzing the password reset endpoint for authorization weaknesses and discovering that the reset could be completed without proper identity verification.
- **Impact**: Full account takeover of any lemlist user through unauthorized password reset.
- **Key Takeaway**: Password reset endpoints should always be tested for: missing rate limits, predictable tokens, token leakage in referrer headers, lack of token binding to user, and missing expiration.
- **Source**: https://hackerone.com/reports/3378635

### 50. Authentication Token Theft via Open Redirect (lemlist)
- **Severity**: High
- **Bounty**: $500+
- **Program**: lemlist
- **Platform**: HackerOne
- **Description**: Authentication tokens could be stolen via an open redirect vulnerability in lemlist's platform. The redirect endpoint did not validate the target URL, allowing tokens to be exfiltrated to attacker-controlled domains.
- **How Found**: Discovering an open redirect and chaining it with authentication token leakage through the referrer header or URL parameters.
- **Impact**: Authentication token theft enabling session hijacking and unauthorized account access.
- **Key Takeaway**: Open redirects are frequently chained with token theft. Test for: token leakage in redirect URLs, referrer header leakage after redirects, and OAuth token theft via redirect manipulation.
- **Source**: https://hackerone.com/reports/3419636

### 51. libcurl libssh Key Passphrase Bypass (CVE-2025-15224)
- **Severity**: High
- **Bounty**: $2,500+
- **Program**: curl (Internet Bug Bounty)
- **Platform**: HackerOne
- **Description**: The libcurl libssh backend did not implement the CURLSSH_AUTH_AGENT flag correctly. When CURLSSH_AUTH_PUBLICKEY was set, no key passphrase was required for authentication, effectively bypassing passphrase-protected SSH key authentication.
- **How Found**: Code review of libcurl's SSH authentication implementation, identifying that the AGENT flag handling bypassed passphrase requirements.
- **Impact**: SSH key passphrase bypass allowing authentication without the key passphrase when using libcurl-based SSH connections.
- **Key Takeaway**: Authentication bypasses in widely-used libraries (curl, openssl, libssh) have massive downstream impact. Library-level bugs affect thousands of applications.
- **Source**: https://hackerone.com/reports/3480925

### 52. GraphQL Bug Results in Authentication Bypass (HackerOne Case Study)
- **Severity**: Critical
- **Bounty**: $5,000+
- **Program**: Undisclosed (HackerOne customer)
- **Platform**: HackerOne
- **Description**: A GraphQL implementation bug resulted in a complete authentication bypass. The GraphQL schema exposed mutations that did not enforce authentication, allowing unauthenticated users to perform privileged operations.
- **How Found**: Using GraphQL introspection to discover all available mutations, then testing each mutation without authentication to find which ones were improperly protected.
- **Impact**: Complete authentication bypass through GraphQL, allowing unauthenticated access to protected operations and data.
- **Key Takeaway**: Always test GraphQL schemas for unauthenticated access. Run introspection queries without auth tokens and test every discovered mutation and query without credentials.
- **Source**: https://www.hackerone.com/blog/how-graphql-bug-resulted-authentication-bypass

### 53. MFA Bypass and Account Takeover via Inadequate Authentication Logic (HackerOne Case Study)
- **Severity**: Critical
- **Bounty**: $10,000+
- **Program**: Undisclosed (HackerOne customer)
- **Platform**: HackerOne
- **Description**: Inadequate authentication logic led to an MFA bypass and full account takeover. The authentication state machine had logical flaws that allowed skipping the MFA verification step while still obtaining a fully authenticated session.
- **How Found**: Analyzing the multi-step authentication flow for state machine inconsistencies, finding that specific request sequences could bypass the MFA step.
- **Impact**: Complete MFA bypass enabling account takeover on all MFA-protected accounts.
- **Key Takeaway**: Multi-step authentication flows create complex state machines. Map out all possible state transitions and test for: step skipping, step reordering, parallel execution, and partial completion persistence.
- **Source**: https://www.hackerone.com/blog/how-inadequate-authentication-logic-led-mfa-bypass-and-account-takeover

### 54. Revive Adserver Authorization Bypass - Email Update Without Password (CVE-2024)
- **Severity**: Critical
- **Bounty**: $500+
- **Program**: Revive Adserver
- **Platform**: HackerOne
- **Description**: The admin panel endpoint accepted a POST that updated a user's email without requiring the account password, and the application did not require re-authentication before updating email addresses, enabling account takeover through email change.
- **How Found**: Testing the email update functionality for re-authentication requirements and discovering that the current password was not required for email changes.
- **Impact**: Account takeover by changing the account email without knowing the current password, then using the forgot password flow with the new email.
- **Key Takeaway**: Email change without re-authentication is a critical vulnerability. Always test: password change, email change, 2FA disable, and account deletion for re-authentication requirements.
- **Source**: https://hackerone.com/reports/3398283

### 55. Account Takeover via Host Header Injection in Password Reset
- **Severity**: High
- **Bounty**: $2,000+
- **Program**: Multiple programs
- **Platform**: Various
- **Description**: Password reset poisoning through Host header injection where the application used the Host header value to construct the password reset URL. By manipulating the Host header, attackers could redirect reset links to attacker-controlled domains.
- **How Found**: Modifying the Host header, X-Forwarded-Host, and X-Forwarded-For headers in password reset requests and checking if the reset URL in the email changed accordingly.
- **Impact**: Account takeover by intercepting password reset tokens when victims click poisoned reset links.
- **Key Takeaway**: Test password reset requests with modified Host headers. Also try: X-Forwarded-Host, X-Original-URL, X-Rewrite-URL, and Referer headers. Check the resulting email for URL changes.
- **Source**: https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning

### 56. One-Click Account Takeover Using OAuth Token Theft (Logitech)
- **Severity**: Critical
- **Bounty**: $500+
- **Program**: Logitech
- **Platform**: HackerOne
- **Description**: A one-click account takeover vulnerability in Logitech's platform used OAuth token theft to hijack user sessions. A crafted link could steal the OAuth authentication token when clicked by the victim.
- **How Found**: Discovering an OAuth flow vulnerability that leaked tokens through redirect manipulation, creating a one-click exploit chain.
- **Impact**: Full account takeover of Logitech user accounts with a single click.
- **Key Takeaway**: OAuth token theft through crafted links is a common pattern. Look for open redirects, referrer header leaks, and postMessage vulnerabilities that can steal OAuth tokens.
- **Source**: https://hackerone.com/reports/1046630

### 57. Account Takeover of Existing Users via Authentication Bypass (HackerOne)
- **Severity**: Critical
- **Bounty**: $5,000+
- **Program**: HackerOne
- **Platform**: HackerOne
- **Description**: An authentication bypass vulnerability on the HackerOne platform itself allowed taking over existing user accounts through a flaw in the authentication logic.
- **How Found**: Testing HackerOne's own authentication endpoints for logical flaws and edge cases.
- **Impact**: Account takeover of any existing HackerOne user, potentially including program managers and security researchers.
- **Key Takeaway**: Even the most security-conscious platforms have vulnerabilities. Test the authentication of the bug bounty platform itself - it is a high-value target with potentially sensitive data.
- **Source**: https://hackerone.com/reports/3178999

### 58. Login CSRF Leading to Account Takeover via SAML SSO (HackerOne)
- **Severity**: High
- **Bounty**: $500+
- **Program**: HackerOne
- **Platform**: HackerOne
- **Description**: A Login CSRF vulnerability in HackerOne's SAML SSO flow allowed an attacker to force a victim to authenticate to the attacker's account, or manipulate the SSO flow to gain access to the victim's session.
- **How Found**: Testing the SAML SSO login flow for CSRF protections, discovering that the SAML authentication initiation did not have adequate anti-CSRF measures.
- **Impact**: Session manipulation through Login CSRF, potentially leading to account data exposure or session hijacking.
- **Key Takeaway**: Login CSRF is often overlooked but can be chained with SSO flows for account takeover. Test if the SSO initiation endpoint is protected against CSRF.
- **Source**: https://hackerone.com/reports/171398

### 59. Improper Handling of Authentication Leading to Access Bypass (lemlist)
- **Severity**: High
- **Bounty**: $500+
- **Program**: lemlist
- **Platform**: HackerOne
- **Description**: Improper handling of authentication tokens at app.lemlist.com allowed bypassing access controls. The application did not properly validate or expire authentication tokens in certain scenarios.
- **How Found**: Testing token handling edge cases including expired tokens, revoked tokens, and tokens from deleted sessions.
- **Impact**: Unauthorized access to lemlist user accounts through improperly handled authentication tokens.
- **Key Takeaway**: Test authentication token lifecycle thoroughly: creation, validation, expiration, revocation, and cleanup. Tokens that persist after logout or password change are a common finding.
- **Source**: https://hackerone.com/reports/1420697

### 60. Admin Panel Access Without Authentication (lemlist)
- **Severity**: Critical
- **Bounty**: $500+
- **Program**: lemlist
- **Platform**: HackerOne
- **Description**: The admin panel at app.lemlist.com was accessible without proper authentication, allowing any user to access administrative functionality that should have been restricted to authorized administrators.
- **How Found**: Direct browsing to admin panel URLs and discovering that authentication was not enforced for administrative endpoints.
- **Impact**: Full administrative access to lemlist's platform, including user management, configuration, and data access.
- **Key Takeaway**: Always test for forced browsing to admin endpoints. Try common admin paths (/admin, /dashboard, /manage, /internal) both authenticated and unauthenticated.
