# Race Condition Bug Bounty Reports

> A collection of accepted/disclosed Race Condition vulnerability reports from bug bounty programs. Race conditions are difficult to find and detect, yet they can have severe financial and security impacts.

---

### 1. Race Condition Leads to Duplicate Payouts (HackerOne)
- **Severity:** High
- **Vulnerability Type:** Race Condition in Payment Processing
- **Platform:** HackerOne
- **Program:** HackerOne
- **Bounty:** $2,500+
- **Description:** A race condition in HackerOne's payment system caused duplicate payouts for bounties. When multiple payment processing requests were sent simultaneously, the system processed the same payout multiple times before the first transaction completed and updated the payment status. HackerOne confirmed that companies were never double-charged, but the platform itself absorbed the duplicate payments.
- **How It Was Found:** Sending multiple concurrent requests to the payment processing endpoint, using Turbo Intruder or concurrent HTTP request tools.
- **Impact:** Financial loss through duplicate bounty payments.
- **Key Takeaway:** Payment processing endpoints are the highest-value race condition targets. Test with concurrent requests whenever money is being transferred, awarded, or processed.
- **Source:** https://hackerone.com/reports/220445

### 2. Race Condition in Performing Retests (HackerOne)
- **Severity:** High
- **Vulnerability Type:** Race Condition in Payment
- **Platform:** HackerOne
- **Program:** HackerOne
- **Bounty:** $2,500+ (234 upvotes)
- **Description:** By executing multiple requests to confirm a retest at the same time, a malicious user could be paid multiple times for the retest, allowing stealing of money from HackerOne. The retest confirmation endpoint did not use proper locking mechanisms.
- **How It Was Found:** Sending multiple concurrent POST requests to the retest confirmation endpoint using Turbo Intruder.
- **Impact:** Direct financial theft from HackerOne through multiple retest payments for a single retest action.
- **Key Takeaway:** Any endpoint that triggers a one-time financial action should be tested for race conditions. Use single-packet attack techniques for more reliable race condition exploitation.
- **Source:** https://hackerone.com/reports/429026

### 3. Race Condition in Flag Submission (HackerOne CTF)
- **Severity:** Medium
- **Vulnerability Type:** Race Condition
- **Platform:** HackerOne
- **Program:** HackerOne
- **Bounty:** $500+
- **Description:** A race condition vulnerability allowed an authenticated user to submit the same CTF flag multiple times simultaneously, increasing the user's points and chances to get an invitation to a private program. The flag validation didn't use proper locking.
- **How It Was Found:** Submitting the same flag multiple times concurrently using parallel HTTP requests.
- **Impact:** Unfair point accumulation, potentially affecting program invitation eligibility.
- **Key Takeaway:** Points/rewards systems that process submissions should be tested for duplicate submission through concurrent requests. This applies to any "submit once" functionality.
- **Source:** https://hackerone.com/reports/454949

### 4. Race Conditions in OAuth 2 API Implementations
- **Severity:** High
- **Vulnerability Type:** Race Condition in OAuth
- **Platform:** HackerOne
- **Program:** Internet Bug Bounty
- **Bounty:** $2,500+
- **Description:** Most OAuth 2 API implementations had race condition vulnerabilities allowing a malicious application to obtain multiple access_token and refresh_token pairs while only one pair should be generated per authorization code exchange. By sending multiple concurrent token exchange requests with the same authorization code, multiple valid sessions could be created.
- **How It Was Found:** Sending multiple concurrent POST requests to the /oauth/token endpoint with the same authorization code.
- **Impact:** Token accumulation allowing persistent access even after token revocation, undermining OAuth security guarantees.
- **Key Takeaway:** OAuth token exchange endpoints are systemic race condition targets. This is a widespread issue affecting many OAuth implementations. Test with concurrent authorization code exchanges.
- **Source:** https://hackerone.com/reports/55140

### 5. Race Condition at Create New Location (Shopify)
- **Severity:** Medium
- **Vulnerability Type:** Race Condition / Limit Bypass
- **Platform:** HackerOne
- **Program:** Shopify
- **Bounty:** $500+
- **Description:** A race condition where it was possible to bypass the limit for the number of locations a store could have by submitting multiple creation requests simultaneously. The application checked the count before insertion but didn't use transactional locking, so concurrent requests could all pass the check.
- **How It Was Found:** Sending multiple concurrent POST requests to create new locations, exceeding the intended limit.
- **Impact:** Bypass of business limits, potential impact on system resources and functionality.
- **Key Takeaway:** Any feature with a count/limit restriction should be tested for race conditions. Limits on: number of items, accounts, API calls, or resource creation can often be bypassed through concurrent requests.
- **Source:** https://hackerone.com/reports/413759

### 6. Race Condition in Flash Workers (Double Free)
- **Severity:** Critical
- **Vulnerability Type:** Race Condition / Memory Corruption
- **Platform:** HackerOne
- **Program:** Internet Bug Bounty
- **Bounty:** $2,500+
- **Description:** If one Flash worker called bytearray.compress() while another worker used that bytearray, Flash did not correctly handle the race, potentially causing a double free of the array. This memory corruption could lead to code execution.
- **How It Was Found:** Source code analysis and concurrent operation testing in Flash's multi-threaded worker architecture.
- **Impact:** Memory corruption leading to potential RCE through double-free exploitation.
- **Key Takeaway:** Multi-threaded applications with shared memory are vulnerable to race conditions that cause memory corruption (double free, use-after-free). These are critical severity when they lead to code execution.
- **Source:** https://hackerone.com/reports/47227

### 7. Race Condition to Redeem Multiple Gift Cards (Reverb.com)
- **Severity:** High
- **Vulnerability Type:** Race Condition / Financial
- **Platform:** HackerOne
- **Program:** Reverb.com
- **Bounty:** $500+
- **Description:** A race condition allowed redemption of the same gift card multiple times by sending concurrent redemption requests. The application checked the gift card balance and deducted it, but concurrent requests could all pass the balance check before any deduction was applied.
- **How It Was Found:** Sending multiple concurrent gift card redemption requests using the same gift card code.
- **Impact:** Financial loss through multiple redemptions of a single gift card, effectively multiplying the gift card's value.
- **Key Takeaway:** Gift card and credit redemption systems are classic race condition targets. The check-then-act pattern (check balance -> deduct balance) without atomic operations is inherently vulnerable to TOCTOU attacks.
- **Source:** https://hackerone.com/reports/759247

### 8. Race Condition in Faucet (Cosmos)
- **Severity:** High
- **Vulnerability Type:** Race Condition / Financial
- **Platform:** HackerOne
- **Program:** Cosmos
- **Bounty:** $2,000+
- **Description:** A race condition in the cryptocurrency faucet when using special conditions allowed users to receive multiple payouts from the faucet by sending concurrent requests. The faucet's rate limiting was vulnerable to concurrent request bypass.
- **How It Was Found:** Sending multiple concurrent requests to the faucet endpoint, exploiting the time window between request validation and payout recording.
- **Impact:** Unauthorized multiplication of cryptocurrency payouts from the faucet.
- **Key Takeaway:** Cryptocurrency and blockchain applications are high-value race condition targets. Faucets, token minting, and transfer endpoints should all be tested for concurrent request vulnerabilities.
- **Source:** https://hackerone.com/reports/1438052

### 9. Race Condition in Invite User Action (Omise)
- **Severity:** Medium
- **Vulnerability Type:** Race Condition
- **Platform:** HackerOne
- **Program:** Omise
- **Bounty:** $500+
- **Description:** A race condition in the invite user action allowed sending multiple invitations simultaneously, potentially bypassing invitation limits or creating duplicate user accounts.
- **How It Was Found:** Sending concurrent invite requests for the same user or exceeding invite limits through parallel requests.
- **Impact:** Bypass of invitation limits, potential for unauthorized access through duplicate invitations.
- **Key Takeaway:** User invitation and registration systems should be tested for race conditions. Duplicate account creation through concurrent registration can have cascading effects on access control.
- **Source:** https://hackerone.com/reports/1285538

### 10. Race Condition in Popular Bug Bounty Programs (Research)
- **Severity:** Various
- **Vulnerability Type:** Race Condition (Research)
- **Platform:** HackerOne
- **Program:** HackerOne
- **Bounty:** $500+ (multiple reports)
- **Description:** Research into race conditions across popular HackerOne programs revealed that many common operations were vulnerable, including: report submission, bounty claiming, invitation acceptance, and feature toggling.
- **How It Was Found:** Systematic concurrent request testing across multiple endpoints and programs.
- **Impact:** Various - from duplicate reports to unauthorized access.
- **Key Takeaway:** Race conditions are underreported and present across many programs. Systematic testing of all state-changing endpoints with concurrent requests can yield multiple findings.
- **Source:** https://hackerone.com/reports/146845

### 11. Race Condition in Money Transfer
- **Severity:** Critical
- **Vulnerability Type:** Race Condition / Financial
- **Platform:** Various
- **Program:** Multiple (Financial platforms)
- **Bounty:** $5,000-$25,000
- **Description:** Race conditions in money transfer features where sending concurrent transfer requests could result in: transferring more money than the account balance, double-spending, or creating money out of thin air. The balance check and deduction were not atomic.
- **How It Was Found:** Sending multiple concurrent money transfer requests for amounts near or equal to the account balance.
- **Impact:** Direct financial theft through double-spending or balance bypass.
- **Key Takeaway:** Financial transfer endpoints are the most impactful race condition targets. Test with: full balance transfers concurrently, multiple small transfers exceeding balance, and transfers during deposit/withdrawal processing.
- **Source:** Multiple bug bounty reports

### 12. Race Condition in Coupon Application
- **Severity:** High
- **Vulnerability Type:** Race Condition / Business Logic
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $1,000-$5,000
- **Description:** Applying the same coupon code concurrently could result in the coupon being applied multiple times to the same order, stacking discounts beyond intended limits.
- **How It Was Found:** Sending concurrent coupon application requests with the same code using Turbo Intruder or Burp Repeater (parallel mode).
- **Impact:** Excessive discounts leading to financial loss.
- **Key Takeaway:** Coupon and promotional code systems are frequently vulnerable to race conditions. The "check if used -> mark as used" pattern is inherently racy without database-level locking.
- **Source:** Multiple bug bounty reports

### 13. Race Condition in Account Follow/Unfollow
- **Severity:** Low
- **Vulnerability Type:** Race Condition
- **Platform:** Various
- **Program:** Multiple (Social Media)
- **Bounty:** $100-$500
- **Description:** Race conditions in follow/unfollow functionality could result in inconsistent follower counts, duplicate follow entries, or bypass of follow limits.
- **How It Was Found:** Sending concurrent follow requests and checking if the follower count increases beyond expected values.
- **Impact:** Follower count manipulation, potential bypass of follow limits.
- **Key Takeaway:** While low severity, social media race conditions demonstrate the concept. This same pattern at higher-impact endpoints (payments, transfers) becomes critical.
- **Source:** Multiple bug bounty reports

### 14. Race Condition in Two-Factor Authentication
- **Severity:** High
- **Vulnerability Type:** Race Condition / Authentication Bypass
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $2,000-$10,000
- **Description:** Race conditions in 2FA verification where sending multiple concurrent verification requests with different codes could bypass rate limiting or lockout mechanisms, allowing brute-force of 2FA codes.
- **How It Was Found:** Sending concurrent 2FA verification requests with different OTP codes using Turbo Intruder.
- **Impact:** 2FA bypass through race condition-assisted brute force.
- **Key Takeaway:** 2FA endpoints with limited code space (6-digit codes = 1M possibilities) should be tested for race conditions that bypass rate limiting. The single-packet attack technique makes this more reliable.
- **Source:** Multiple bug bounty reports

### 15. Race Condition in File Upload
- **Severity:** Medium-High
- **Vulnerability Type:** Race Condition / TOCTOU
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $500-$3,000
- **Description:** Time-of-check to time-of-use (TOCTOU) race conditions in file upload where a file passes validation checks (type, size, content) but is replaced or modified between validation and storage/processing.
- **How It Was Found:** Uploading a file that passes validation, then rapidly replacing it with a malicious file before the server finishes processing.
- **Impact:** Upload of malicious files (web shells, malware) that bypass validation.
- **Key Takeaway:** File upload TOCTOU races are particularly dangerous when the validation and processing happen asynchronously. Test by rapidly uploading and replacing files.
- **Source:** Multiple bug bounty reports

### 16. Race Condition in Voting/Rating Systems
- **Severity:** Low-Medium
- **Vulnerability Type:** Race Condition
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $100-$1,000
- **Description:** Voting and rating systems that prevent duplicate votes can be bypassed through concurrent vote submissions. The "check if voted -> record vote" pattern is vulnerable to race conditions.
- **How It Was Found:** Sending concurrent vote requests using Turbo Intruder's single-packet attack.
- **Impact:** Vote manipulation, unfair content ranking.
- **Key Takeaway:** Any "one-time action" (vote once, claim once, submit once) should be tested with concurrent requests. The more impactful the one-time action, the higher the severity.
- **Source:** Multiple bug bounty reports

### 17. Race Condition in API Rate Limiting
- **Severity:** Medium
- **Vulnerability Type:** Race Condition / Rate Limit Bypass
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $500-$2,000
- **Description:** API rate limiting mechanisms that check request counts before incrementing the counter can be bypassed through concurrent requests that all pass the check before any increment is recorded.
- **How It Was Found:** Sending a burst of concurrent requests and checking if more requests succeed than the rate limit allows.
- **Impact:** Rate limit bypass enabling brute force attacks, data scraping, or DoS.
- **Key Takeaway:** Rate limiting implementations should be tested with concurrent requests. If you can send 100 concurrent requests and they all succeed despite a rate limit of 10, the rate limiting is vulnerable to race conditions.
- **Source:** Multiple bug bounty reports

### 18. Race Condition in Subscription Activation
- **Severity:** High
- **Vulnerability Type:** Race Condition
- **Platform:** Various
- **Program:** Multiple (SaaS)
- **Bounty:** $1,000-$5,000
- **Description:** Race conditions in subscription activation where sending concurrent activation requests with a single-use activation code could create multiple active subscriptions from one payment.
- **How It Was Found:** Sending concurrent subscription activation requests with the same activation/license code.
- **Impact:** Multiple subscription activations from a single payment, revenue loss.
- **Key Takeaway:** License/activation code redemption is vulnerable to the same race condition patterns as gift cards and coupons. Any single-use code redemption should be tested.
- **Source:** Multiple bug bounty reports

### 19. Race Condition in Password Reset Token Generation
- **Severity:** Medium
- **Vulnerability Type:** Race Condition
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $500-$2,000
- **Description:** Concurrent password reset requests could generate multiple valid reset tokens for the same account, or interfere with the token invalidation process, allowing an attacker to use an older token even after a newer one was generated.
- **How It Was Found:** Sending concurrent password reset requests and testing if multiple reset links remain valid simultaneously.
- **Impact:** Account takeover through token manipulation in password reset flows.
- **Key Takeaway:** Password reset token generation should invalidate all previous tokens atomically. Test if sending concurrent reset requests creates multiple valid tokens.
- **Source:** Multiple bug bounty reports

### 20. Race Condition in Database Migrations (Double Insert)
- **Severity:** Medium
- **Vulnerability Type:** Race Condition / Data Integrity
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $500-$2,000
- **Description:** Race conditions in unique constraint enforcement where concurrent insert operations could both pass the uniqueness check before either record is committed, resulting in duplicate entries that violate business rules.
- **How It Was Found:** Sending concurrent registration/creation requests with identical unique fields (email, username).
- **Impact:** Duplicate accounts, data integrity violations, potential security bypasses.
- **Key Takeaway:** Database-level unique constraints are more reliable than application-level checks, but even database constraints can be bypassed in some isolation levels. Test with concurrent creation requests using identical unique values.
- **Source:** Multiple bug bounty reports

---

## Additional Reports (Expanded Collection)

### 21. Race Condition Leads to Duplicate Transaction Processing (HackerOne)
- **Severity**: Critical
- **Bounty**: $2,500
- **Program**: HackerOne
- **Platform**: HackerOne
- **Description**: A race condition in HackerOne's transaction processing allowed duplicate transactions to be created. By sending concurrent requests to the payment endpoint, the same transaction could be processed multiple times before the first completed.
- **How Found**: Sending parallel requests to the transaction processing endpoint using Turbo Intruder's single-packet attack technique.
- **Impact**: Financial loss through duplicate transaction processing on the platform.
- **Key Takeaway**: Any endpoint that processes financial transactions should be tested with concurrent requests. The single-packet attack technique eliminates network jitter for more reliable exploitation.
- **Source**: https://hackerone.com/reports/604534

### 22. Client-Side Race Condition Using Marketo Forms (HackerOne)
- **Severity**: Medium
- **Bounty**: $500
- **Program**: HackerOne
- **Platform**: HackerOne
- **Description**: A client-side race condition using Marketo allowed sending users to a data-protocol URL in Safari when a form without an onSuccess handler was submitted. By winning the race, an attacker could redirect users to a malicious data URI.
- **How Found**: Analyzing the Marketo form integration and identifying a timing window between form submission and the success handler execution.
- **Impact**: Client-side redirect to malicious content in Safari, potential for phishing or script execution.
- **Key Takeaway**: Client-side race conditions are less common but still exploitable. Look for timing windows between JavaScript event handlers and DOM updates.
- **Source**: https://hackerone.com/reports/202767

### 23. Race Condition on Krisp API Subscription
- **Severity**: High
- **Bounty**: $1,000+
- **Program**: Krisp
- **Platform**: HackerOne
- **Description**: A race condition on api.krisp.ai allowed creating multiple subscriptions from a single payment. By sending concurrent subscription activation requests, the system processed multiple activations before marking the payment as used.
- **How Found**: Sending concurrent POST requests to the subscription activation endpoint using the same payment token.
- **Impact**: Multiple premium subscriptions from a single payment, causing revenue loss.
- **Key Takeaway**: SaaS subscription activation endpoints are high-value race condition targets. Test with concurrent activation requests using the same payment/license token.
- **Source**: https://hackerone.com/reports/1418419

### 24. Race Condition in Report Retesting Payment (HackerOne)
- **Severity**: High
- **Bounty**: $2,500
- **Program**: HackerOne
- **Platform**: HackerOne
- **Description**: By executing multiple requests to confirm a retest simultaneously, a researcher could receive multiple payments for a single retest. The retest confirmation endpoint lacked proper mutex/locking, allowing the payment to be triggered multiple times.
- **How Found**: Using Turbo Intruder to send multiple concurrent POST requests to the retest confirmation endpoint, observing that multiple payments were issued.
- **Impact**: Direct financial theft from HackerOne through duplicate retest payments.
- **Key Takeaway**: The single-packet attack technique is highly effective against payment endpoints. Any one-time payment trigger should use database-level locking.
- **Source**: https://hackerone.com/reports/429026

### 25. Race Condition in Shopify Location Limit Bypass
- **Severity**: Medium
- **Bounty**: $1,600
- **Program**: Shopify
- **Platform**: HackerOne
- **Description**: By sending concurrent requests to create new locations, a Shopify store could exceed its plan-based location limit. The limit check and location creation were not atomic operations.
- **How Found**: Scripting concurrent POST requests to the location creation endpoint while already at the plan's location limit.
- **Impact**: Bypassing plan-based resource limits, potentially accessing features beyond the current subscription tier.
- **Key Takeaway**: Plan-based limits (resource counts, user seats, storage) are race condition targets. Send concurrent creation requests when at the limit boundary.
- **Source**: https://hackerone.com/reports/413759

### 26. Race Condition in Gift Card Redemption (Reverb.com)
- **Severity**: High
- **Bounty**: $1,000
- **Program**: Reverb.com
- **Platform**: HackerOne
- **Description**: A race condition in Reverb.com's gift card redemption system allowed the same gift card to be redeemed multiple times simultaneously. The balance check and deduction were not performed as an atomic database operation.
- **How Found**: Sending concurrent gift card redemption requests using the same gift card code, each requesting the full balance amount.
- **Impact**: Multiplying gift card value, creating unauthorized store credit for financial theft.
- **Key Takeaway**: The classic TOCTOU pattern: check balance -> deduct balance. Without atomic operations or pessimistic locking, this is always vulnerable. Gift card, voucher, and credit systems should be primary targets.
- **Source**: https://hackerone.com/reports/759247

### 27. Race Condition in Cosmos Faucet Payout
- **Severity**: High
- **Bounty**: $2,000
- **Program**: Cosmos
- **Platform**: HackerOne
- **Description**: A race condition in the Cosmos blockchain faucet allowed users to receive multiple cryptocurrency payouts by sending concurrent requests. The faucet's rate limiting was checked before payout but not enforced atomically.
- **How Found**: Sending multiple concurrent requests to the faucet endpoint with the same wallet address, exploiting the window between rate-limit check and payout recording.
- **Impact**: Unauthorized multiplication of cryptocurrency payouts from the faucet.
- **Key Takeaway**: Blockchain faucets and token distribution endpoints are high-value targets. The immutable nature of blockchain transactions makes race conditions here particularly impactful.
- **Source**: https://hackerone.com/reports/1438052

### 28. Race Condition in OAuth Authorization Code Exchange
- **Severity**: High
- **Bounty**: $2,500
- **Program**: Internet Bug Bounty
- **Platform**: HackerOne
- **Description**: Most OAuth 2 implementations were vulnerable to race conditions during authorization code exchange. Sending concurrent token requests with the same authorization code generated multiple valid access/refresh token pairs, undermining token revocation.
- **How Found**: Capturing an OAuth authorization code and sending it to the /oauth/token endpoint in multiple concurrent requests before the first response invalidated the code.
- **Impact**: Multiple valid sessions from a single authorization, making token revocation ineffective and enabling persistent unauthorized access.
- **Key Takeaway**: OAuth token exchange is a systemic race condition target. This affects many implementations because the "use code, then invalidate" pattern is inherently racy without atomic database operations.
- **Source**: https://hackerone.com/reports/55140

### 29. Race Condition in Flash Worker ByteArray (Double Free)
- **Severity**: Critical
- **Bounty**: $10,000
- **Program**: Internet Bug Bounty
- **Platform**: HackerOne
- **Description**: When one Flash worker called bytearray.compress() while another worker used that bytearray, Flash failed to handle the race correctly, causing a double free. This memory corruption was exploitable for arbitrary code execution.
- **How Found**: Source code analysis of Flash's multi-threaded worker architecture, identifying shared memory operations without proper synchronization primitives.
- **Impact**: Remote code execution through memory corruption caused by the race condition.
- **Key Takeaway**: Race conditions in native code (C/C++) can cause memory corruption (double free, use-after-free) leading to RCE. These are critical severity and often attract the highest bounties.
- **Source**: https://hackerone.com/reports/47227

### 30. HTTP Request Smuggling via Race Condition (Basecamp)
- **Severity**: Critical
- **Bounty**: $7,500
- **Program**: Basecamp
- **Platform**: HackerOne
- **Description**: An HTTP/2 request smuggling vulnerability in Basecamp's infrastructure exploited race conditions in how the front-end and back-end servers parsed HTTP requests. The desync allowed injecting requests into other users' connections.
- **How Found**: Using HTTP/2-specific smuggling techniques to exploit the HTTP/2 to HTTP/1.1 downgrade path, creating request boundary desynchronization.
- **Impact**: Cache poisoning, session hijacking, and cross-user request injection affecting all Basecamp users.
- **Key Takeaway**: HTTP/2 to HTTP/1.1 downgrade is a growing race condition attack surface. Modern CDN/load balancer architectures that perform protocol downgrades are particularly vulnerable.
- **Source**: https://hackerone.com/reports/919175

### 31. Race Condition in Password Theft via Request Smuggling (New Relic)
- **Severity**: Critical
- **Bounty**: $3,000
- **Program**: New Relic
- **Platform**: HackerOne
- **Description**: A request smuggling vulnerability on login.newrelic.com enabled password theft through a race condition in how the front-end and back-end servers processed HTTP requests. The smuggled request could capture other users' login credentials.
- **How Found**: Testing the login endpoint for HTTP request smuggling via Content-Length/Transfer-Encoding desync, then demonstrating credential capture.
- **Impact**: Theft of user passwords during login, affecting any New Relic user who logged in while the attack was active.
- **Key Takeaway**: Request smuggling on login endpoints is particularly dangerous because it can capture plaintext credentials. Login pages should be prioritized for smuggling tests.
- **Source**: https://hackerone.com/reports/498052

### 32. Race Condition in Multiple HTTP Smuggling Vectors (Cloudflare)
- **Severity**: High
- **Bounty**: $3,100
- **Program**: Cloudflare
- **Platform**: HackerOne
- **Description**: HTTP request smuggling with Origin Rules using newlines in the host_header action parameter exploited race conditions in Cloudflare's request processing pipeline.
- **How Found**: Testing Cloudflare's Origin Rules feature for request smuggling by injecting newline characters in the host_header action parameter.
- **Impact**: Request smuggling through Cloudflare's infrastructure, potentially affecting sites protected by Cloudflare.
- **Key Takeaway**: CDN and WAF providers are high-value smuggling targets because a single vulnerability can affect millions of sites. Test CDN-specific features for smuggling vectors.
- **Source**: https://hackerone.com/reports/648434

### 33. Race Condition in Email Verification (Account Takeover)
- **Severity**: High
- **Bounty**: $2,000-$5,000
- **Program**: Multiple
- **Platform**: Various
- **Description**: Race conditions in email verification where concurrent verification requests with different email addresses could cause the system to verify an attacker's email on a victim's account. The email verification and account update were not atomic.
- **How Found**: Sending concurrent email verification requests, one with the victim's token and one with the attacker's modified email, to exploit the verification timing window.
- **Impact**: Account takeover through email address substitution during verification.
- **Key Takeaway**: Email verification flows should atomically verify that the token matches the email being confirmed. Test concurrent verification with different email addresses.
- **Source**: Multiple bug bounty reports

### 34. Race Condition in Promo Code Stacking
- **Severity**: High
- **Bounty**: $2,000-$5,000
- **Program**: Multiple (E-commerce)
- **Platform**: Various
- **Description**: Promotional codes that should be mutually exclusive could be stacked through concurrent application requests. The system checked if a promo was already applied before adding a new one, but concurrent requests all passed the check.
- **How Found**: Sending concurrent requests to apply different promo codes to the same cart/order simultaneously.
- **Impact**: Excessive discounts through promo code stacking, potentially reducing the order total to zero.
- **Key Takeaway**: Promo code mutual exclusivity should be enforced with database-level constraints, not application-level checks. Test with concurrent applications of different codes.
- **Source**: Multiple bug bounty reports

### 35. Race Condition in Referral Bonus Claiming
- **Severity**: High
- **Bounty**: $1,000-$3,000
- **Program**: Multiple (Fintech/Ride-sharing)
- **Platform**: Various
- **Description**: Referral bonus systems where the bonus was claimed when the referred user completed a qualifying action. Concurrent requests to claim the bonus resulted in multiple payouts for a single referral.
- **How Found**: Triggering the qualifying action (first purchase, account verification) and simultaneously sending multiple referral bonus claim requests.
- **Impact**: Multiple referral bonuses from a single referral, causing financial loss.
- **Key Takeaway**: Referral bonus claiming should use idempotency keys or database-level constraints to prevent duplicate claims. Test the claiming endpoint with concurrent requests.
- **Source**: Multiple bug bounty reports

### 36. Race Condition in Inventory Reservation
- **Severity**: Medium
- **Bounty**: $500-$2,000
- **Program**: Multiple (E-commerce)
- **Platform**: Various
- **Description**: Limited-stock items could be over-reserved through concurrent purchase requests. The stock check and reservation were not atomic, allowing more reservations than available inventory.
- **How Found**: Sending concurrent purchase requests for a product with limited stock (e.g., 1 remaining), checking if multiple orders were created.
- **Impact**: Overselling of limited inventory, fulfillment issues, and customer dissatisfaction.
- **Key Takeaway**: Inventory management systems should use database-level locking for stock reservation. Flash sales and limited-edition drops are particularly vulnerable.
- **Source**: Multiple bug bounty reports

### 37. Race Condition in Session Token Rotation
- **Severity**: Medium
- **Bounty**: $500-$2,000
- **Program**: Multiple
- **Platform**: Various
- **Description**: Session token rotation (generating new tokens on privilege change) had a race condition where both the old and new tokens remained valid. Concurrent requests during token rotation could cause the old token to persist.
- **How Found**: Triggering a session token rotation (password change, privilege escalation) and simultaneously using the old token in concurrent requests.
- **Impact**: Persistent access with invalidated tokens, undermining session security.
- **Key Takeaway**: Session token rotation should atomically invalidate old tokens. Test if old session tokens remain valid during and after rotation events.
- **Source**: Multiple bug bounty reports

### 38. Race Condition in NFT Minting
- **Severity**: Critical
- **Bounty**: $5,000-$50,000
- **Program**: Multiple (Web3/NFT)
- **Platform**: Various (Immunefi, HackerOne)
- **Description**: NFT minting endpoints vulnerable to race conditions allowed minting more tokens than permitted per wallet or per transaction. The mint count check and actual minting were not atomic.
- **How Found**: Sending concurrent mint requests from the same wallet, exceeding per-wallet limits through the race window.
- **Impact**: Exceeding mint limits, potentially minting the entire collection supply from a single wallet.
- **Key Takeaway**: Web3 applications with off-chain components (minting APIs, whitelists) are vulnerable to traditional race conditions. On-chain and off-chain state can desync.
- **Source**: Multiple Web3 bug bounty reports

### 39. Race Condition in Multi-Factor Authentication Setup
- **Severity**: High
- **Bounty**: $1,000-$5,000
- **Program**: Multiple
- **Platform**: Various
- **Description**: During MFA setup, concurrent requests could bind multiple TOTP secrets to the same account, or bind a secret without completing the verification step. The setup flow's state management was not atomic.
- **How Found**: Sending concurrent MFA setup requests with different TOTP secrets, or completing the setup without the verification step through concurrent requests.
- **Impact**: MFA bypass through binding of attacker-controlled authenticator, or account lockout through invalid MFA binding.
- **Key Takeaway**: MFA setup flows should use atomic state transitions. Test if concurrent setup requests can create conflicting MFA states.
- **Source**: Multiple bug bounty reports

### 40. Race Condition in Concurrent Withdrawal Requests (Crypto Exchange)
- **Severity**: Critical
- **Bounty**: $10,000-$50,000
- **Program**: Multiple (Cryptocurrency Exchanges)
- **Platform**: Various
- **Description**: Cryptocurrency exchanges where concurrent withdrawal requests could drain more funds than the account balance. The balance check occurred before the withdrawal was recorded, creating a window for double-spending.
- **How Found**: Depositing a small amount, then sending many concurrent withdrawal requests for the full balance amount, checking if multiple withdrawals succeeded.
- **Impact**: Direct financial theft through double-spending on the exchange, potentially draining the hot wallet.
- **Key Takeaway**: Cryptocurrency withdrawal endpoints are the highest-value race condition targets. Exchanges should use pessimistic database locking and atomic balance operations.
- **Source**: Multiple cryptocurrency bug bounty reports

### 41. Race Condition in API Key Generation
- **Severity**: Medium
- **Bounty**: $500-$2,000
- **Program**: Multiple
- **Platform**: Various
- **Description**: API key generation endpoints that should create only one key per request could be exploited through concurrent requests to create multiple valid API keys, potentially exceeding per-account key limits.
- **How Found**: Sending concurrent API key generation requests and checking if multiple keys were created.
- **Impact**: Exceeding API key limits, potential for key sprawl and tracking evasion.
- **Key Takeaway**: Any single-generation endpoint should be tested for race conditions. Key generation, token creation, and credential issuance endpoints are all candidates.
- **Source**: Multiple bug bounty reports

### 42. Race Condition in Like/Upvote Amplification
- **Severity**: Low
- **Bounty**: $100-$500
- **Program**: Multiple (Social Media)
- **Platform**: Various
- **Description**: Like and upvote mechanisms that prevent duplicate votes could be bypassed through concurrent requests. By sending multiple like requests simultaneously, a single user could cast multiple votes on the same content.
- **How Found**: Using Turbo Intruder to send concurrent like/upvote requests for the same content item from the same account.
- **Impact**: Content ranking manipulation through artificial vote inflation.
- **Key Takeaway**: While low severity alone, vote manipulation on platforms that use votes for moderation or content promotion can have outsized business impact.
- **Source**: Multiple bug bounty reports

### 43. Race Condition in Webhook Delivery Deduplication
- **Severity**: Medium
- **Bounty**: $500-$1,500
- **Program**: Multiple (Platform/API)
- **Platform**: Various
- **Description**: Webhook delivery systems that should deduplicate events could be tricked into sending duplicate webhooks through race conditions in the deduplication logic. This could cause downstream systems to process the same event multiple times.
- **How Found**: Triggering webhook events through concurrent API calls and monitoring if duplicate webhooks were delivered to the configured endpoint.
- **Impact**: Duplicate event processing in downstream systems, potential for duplicate orders, payments, or notifications.
- **Key Takeaway**: Webhook consumers should implement idempotency, but webhook producers should also test their deduplication logic for race conditions.
- **Source**: Multiple bug bounty reports

### 44. Race Condition in Team Member Role Assignment
- **Severity**: High
- **Bounty**: $1,000-$5,000
- **Program**: Multiple (Collaboration)
- **Platform**: Various
- **Description**: Concurrent requests to modify a team member's role could result in privilege escalation. By sending simultaneous role change requests, one requesting elevation and one requesting the current level, the system could end up granting the elevated role.
- **How Found**: Sending concurrent role modification requests with different target roles for the same team member.
- **Impact**: Unauthorized privilege escalation within team/organization, potentially gaining admin access.
- **Key Takeaway**: Role modification endpoints should use optimistic locking or atomic compare-and-swap operations. Test with concurrent requests setting different role levels.
- **Source**: Multiple bug bounty reports

### 45. Race Condition in Content Publishing Workflow
- **Severity**: Medium
- **Bounty**: $500-$2,000
- **Program**: Multiple (CMS/Publishing)
- **Platform**: Various
- **Description**: Content publishing workflows with approval requirements could be bypassed through race conditions. By submitting content for approval and simultaneously publishing it, the approval check could be bypassed.
- **How Found**: Sending concurrent requests: one to submit for approval and one to directly publish, exploiting the window before approval status was enforced.
- **Impact**: Publishing unapproved content, bypassing editorial controls.
- **Key Takeaway**: Workflow state machines (draft -> review -> approved -> published) should enforce state transitions atomically. Test if concurrent requests can skip states.
- **Source**: Multiple bug bounty reports

### 46. Race Condition in Coupon Generation (Unique Code)
- **Severity**: Medium
- **Bounty**: $500-$2,000
- **Program**: Multiple (E-commerce)
- **Platform**: Various
- **Description**: Systems that generate unique single-use coupon codes had a race condition where the uniqueness check and code generation were not atomic. Concurrent requests could generate duplicate coupon codes.
- **How Found**: Sending concurrent coupon generation requests and checking for duplicate codes in the responses.
- **Impact**: Duplicate coupon codes that could be shared or used multiple times, bypassing single-use restrictions.
- **Key Takeaway**: Unique code generation should use database-level uniqueness constraints and retry logic, not application-level checks.
- **Source**: Multiple bug bounty reports

### 47. Race Condition in Account Merging
- **Severity**: High
- **Bounty**: $2,000-$5,000
- **Program**: Multiple
- **Platform**: Various
- **Description**: Account merging functionality (linking two accounts into one) had race conditions where concurrent merge requests could create inconsistent states, duplicate data, or merge accounts that shouldn't be merged.
- **How Found**: Initiating concurrent account merge requests from both accounts simultaneously, or merging while another operation (deletion, update) was in progress.
- **Impact**: Data corruption, unauthorized data access through incorrect merge, or account duplication.
- **Key Takeaway**: Account merging is a complex operation that touches many data tables. Race conditions here can have cascading effects across the entire user data model.
- **Source**: Multiple bug bounty reports

### 48. Race Condition in Token Bucket Rate Limiter
- **Severity**: Medium
- **Bounty**: $500-$2,000
- **Program**: Multiple
- **Platform**: Various
- **Description**: Token bucket rate limiters implemented at the application level (not using atomic operations) could be bypassed by sending a burst of concurrent requests that all read the token count before any tokens were consumed.
- **How Found**: Sending a large burst of concurrent requests and observing if more requests succeeded than the rate limit should allow.
- **Impact**: Rate limit bypass enabling brute force attacks, data scraping, or denial of service.
- **Key Takeaway**: Rate limiters should use atomic increment/decrement operations (e.g., Redis DECR). Application-level rate limiting with read-then-write patterns is inherently racy.
- **Source**: Multiple bug bounty reports

### 49. Race Condition in Cart-to-Order Conversion
- **Severity**: High
- **Bounty**: $2,000-$5,000
- **Program**: Multiple (E-commerce)
- **Platform**: Various
- **Description**: The conversion of a shopping cart to a finalized order had a race condition where cart modifications could occur between price calculation and order finalization, resulting in the wrong items or prices in the final order.
- **How Found**: Modifying cart contents (adding expensive items, changing quantities) concurrently with the order finalization request.
- **Impact**: Receiving additional items not paid for, or paying a lower price for expensive items.
- **Key Takeaway**: Cart-to-order conversion should snapshot the cart and lock it during finalization. Test if cart modifications during checkout affect the final order.
- **Source**: Multiple bug bounty reports

### 50. Race Condition in Concurrent Password Change and Login
- **Severity**: Medium
- **Bounty**: $500-$2,000
- **Program**: Multiple
- **Platform**: Various
- **Description**: Concurrent password change and login requests could create a state where both the old and new passwords were valid. The session invalidation after password change did not atomically invalidate existing sessions.
- **How Found**: Sending a password change request and simultaneously attempting login with the old password in concurrent requests.
- **Impact**: Persistent access with old credentials after password change, undermining password rotation security.
- **Key Takeaway**: Password changes should atomically invalidate all existing sessions and old credentials. Test if old passwords/sessions remain valid during and after password change.
- **Source**: Multiple bug bounty reports

### 51. Race Condition in Feature Toggle Enforcement
- **Severity**: Medium
- **Bounty**: $500-$1,500
- **Program**: Multiple (SaaS)
- **Platform**: Various
- **Description**: Feature toggles that controlled access to premium or beta features had a race condition between the feature flag check and feature execution. During feature flag updates (enabling/disabling), concurrent requests could access features that were being disabled.
- **How Found**: Monitoring feature flag changes and sending requests during the transition window between enabled and disabled states.
- **Impact**: Unauthorized access to features during toggle transitions, potentially including disabled security controls.
- **Key Takeaway**: Feature flag systems should use consistent reads. Test feature access during the window when flags are being toggled.
- **Source**: Multiple bug bounty reports

### 52. Race Condition in Escrow Release
- **Severity**: Critical
- **Bounty**: $5,000-$20,000
- **Program**: Multiple (Marketplace/Freelance)
- **Platform**: Various
- **Description**: Escrow systems where funds are held until work completion had race conditions in the release mechanism. Concurrent release requests could trigger multiple fund releases from a single escrow balance.
- **How Found**: Sending concurrent escrow release requests using Turbo Intruder when the escrow conditions were met.
- **Impact**: Multiple fund releases from a single escrow, draining the escrow account beyond its balance.
- **Key Takeaway**: Escrow and held-fund systems are critical race condition targets. The release mechanism should use pessimistic locking and atomic balance operations.
- **Source**: Multiple bug bounty reports

### 53. Race Condition in Invite Code Validation
- **Severity**: Medium
- **Bounty**: $500-$2,000
- **Program**: Multiple
- **Platform**: Various
- **Description**: Invite-only platforms where invitation codes had usage limits could be bypassed through concurrent registrations using the same invite code. The usage count check and increment were not atomic.
- **How Found**: Sending concurrent registration requests all using the same invite code, exceeding its usage limit.
- **Impact**: Bypassing invite-only access controls, creating more accounts than the invitation allows.
- **Key Takeaway**: Single-use or limited-use invitation codes should use atomic counter operations. Test with concurrent registrations using the same code.
- **Source**: Multiple bug bounty reports

### 54. Race Condition in Auction Sniping Protection
- **Severity**: Medium
- **Bounty**: $500-$2,000
- **Program**: Multiple (Auction)
- **Platform**: Various
- **Description**: Auction platforms with sniping protection (extending the auction when a last-second bid is placed) had race conditions where bids placed at the exact end time could bypass the extension logic, winning the auction without triggering protection.
- **How Found**: Sending bid requests timed to arrive at the exact auction end time, exploiting the gap between bid processing and extension trigger.
- **Impact**: Circumventing auction fairness mechanisms, winning auctions at unfairly low prices.
- **Key Takeaway**: Time-sensitive business logic (auctions, flash sales, token launches) should handle edge cases at time boundaries. Test with requests timed to arrive at exact cutoff moments.
- **Source**: Multiple bug bounty reports

### 55. Race Condition in Database Seeding/Migration
- **Severity**: Medium
- **Bounty**: $500-$2,000
- **Program**: Multiple
- **Platform**: Various
- **Description**: Application startup procedures that seed default data (admin accounts, default settings) had race conditions when multiple application instances started simultaneously. This could create duplicate admin accounts or inconsistent default configurations.
- **How Found**: Triggering concurrent application restarts and checking for duplicate seed data (multiple admin accounts, duplicate default records).
- **Impact**: Duplicate admin accounts with potentially different passwords, inconsistent application state.
- **Key Takeaway**: Database seeding and migration operations should use advisory locks or leader election. Test application behavior during concurrent instance startups.
- **Source**: Multiple bug bounty reports

---

## Race Condition Hunting Methodology Summary

### Tools Commonly Used
- **Turbo Intruder (Burp Extension)** - Single-packet attack for precise race conditions
- **Burp Repeater** - Group requests and send in parallel
- **race-the-web** - Race condition testing tool
- **Custom Python/Go scripts** - Concurrent HTTP request scripts
- **curl with parallel** - Quick concurrent request testing

### Single-Packet Attack Technique
The most reliable method for exploiting race conditions, developed by James Kettle (PortSwigger):
1. Prepare multiple HTTP requests
2. Send all requests in a single TCP packet
3. This ensures all requests arrive at the server simultaneously
4. Eliminates network jitter that might cause failures

### Common Race Condition Targets
1. **Financial operations** - Payments, transfers, refunds
2. **Single-use codes** - Coupons, gift cards, activation codes
3. **OAuth token exchange** - Authorization code -> token
4. **Rate-limited endpoints** - Login, 2FA verification
5. **One-time actions** - Vote, follow, submit flag
6. **Resource creation with limits** - Accounts, locations, items
7. **Balance checks** - Check-then-act patterns
8. **Token generation** - Password reset, session creation
9. **File upload processing** - TOCTOU between validation and storage
10. **Invitation/referral systems** - Duplicate invitation prevention

### Key Concepts
- **TOCTOU (Time of Check to Time of Use)** - The fundamental pattern behind most race conditions
- **Atomicity** - Operations that should be atomic but aren't
- **Isolation** - Database transaction isolation levels affect exploitability
- **Idempotency** - Operations that should produce the same result regardless of how many times they're called
