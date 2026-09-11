# Business Logic Flaw Bug Bounty Reports

> A collection of accepted/disclosed Business Logic vulnerability reports from bug bounty programs. Business logic errors represent ~2% of all vulnerabilities reported on HackerOne, yet 45% of total bounty awards go toward business logic findings, making them among the highest-value vulnerability types.

---

### 1. Business Logic Flaw - Non-Premium User Accessing Premium Features (Curve)
- **Severity:** High
- **Vulnerability Type:** Business Logic Flaw / Authorization Bypass
- **Platform:** HackerOne
- **Program:** Curve
- **Bounty:** $1,000+
- **Description:** A non-premium user could update and change retailers in the Curve financial application through a business logic flaw. The application did not properly validate the user's subscription tier before allowing premium-only actions.
- **How It Was Found:** Testing premium feature endpoints with a non-premium account, intercepting and replaying requests meant for premium users.
- **Impact:** Free access to premium features, revenue loss for the company, and unfair advantage for the attacker.
- **Key Takeaway:** Always test premium/paid features with free-tier accounts. Intercept requests when using premium features and replay them from a free account. Many applications only enforce subscription checks in the UI, not the backend.
- **Source:** https://hackerone.com/reports/672487

### 2. Unlimited Discount Redemption via Business Logic Flaw (HackerOne Blog)
- **Severity:** High
- **Vulnerability Type:** Business Logic Flaw / Coupon Abuse
- **Platform:** HackerOne
- **Program:** Undisclosed
- **Bounty:** Significant
- **Description:** A business logic vulnerability allowed unlimited discount coupon redemption. The application did not validate the number of times a coupon code could be used, so attackers could apply the same coupon repeatedly to get unlimited discounts or even negative pricing.
- **How It Was Found:** Testing the coupon/discount application flow by: applying the same coupon multiple times, manipulating the discount amount, and testing concurrent coupon applications.
- **Impact:** Direct financial loss through unlimited discount abuse.
- **Key Takeaway:** E-commerce discount systems are prime business logic targets. Test for: reusing coupon codes, stacking multiple coupons, applying coupons to already-discounted items, and manipulating discount values in requests.
- **Source:** https://www.hackerone.com/blog/how-business-logic-vulnerability-led-unlimited-discount-redemption

### 3. Logical Issue - Boosting Reputation (HackerOne)
- **Severity:** Medium
- **Vulnerability Type:** Business Logic Flaw
- **Platform:** HackerOne
- **Program:** HackerOne
- **Bounty:** $500+
- **Description:** A logical issue in HackerOne's reputation system allowed users to artificially boost their reputation scores. The reputation calculation could be manipulated through specific patterns of activity.
- **How It Was Found:** Analyzing the reputation calculation algorithm and finding edge cases that could be exploited to gain unearned reputation points.
- **Impact:** Unfair reputation inflation, potentially affecting program invitation eligibility and trust scores.
- **Key Takeaway:** Gamification systems (reputation, points, badges, levels) are business logic targets. Analyze how points are calculated and look for ways to earn points without legitimate activity.
- **Source:** https://hackerone.com/reports/60429

### 4. Business Logic Flaw Allowing Bypass of Restrictions (Inflection)
- **Severity:** High
- **Vulnerability Type:** Business Logic Flaw
- **Platform:** HackerOne
- **Program:** Inflection
- **Bounty:** $1,000+
- **Description:** A business logic flaw allowed users to bypass restrictions that should have limited their actions within the application. The enforcement of business rules was inconsistent between the frontend and backend.
- **How It Was Found:** Identifying restrictions in the UI, then testing if the same restrictions were enforced at the API level by sending direct API requests.
- **Impact:** Bypass of intended access restrictions and business rule enforcement.
- **Key Takeaway:** Any restriction you see in the UI should be tested at the API level. Frontend-only restrictions are a common source of business logic vulnerabilities.
- **Source:** https://hackerone.com/reports/280914

### 5. Password Change Without Verification (UPchieve)
- **Severity:** High
- **Vulnerability Type:** Business Logic Error
- **Platform:** HackerOne
- **Program:** UPchieve
- **Bounty:** $500+
- **Description:** The password change functionality had a business logic error where there was no verification of the current password. An attacker who obtained temporary session access could permanently take over the account.
- **How It Was Found:** Testing the password change endpoint to verify if current password was required and validated.
- **Impact:** Account takeover through session hijacking or CSRF targeting the password change feature.
- **Key Takeaway:** Sensitive account operations (password change, email change, 2FA changes) should require re-authentication. The absence of re-authentication is a business logic flaw.
- **Source:** https://hackerone.com/reports/1296597

### 6. Browser Cache Not Cleared on Logout (Localize)
- **Severity:** Medium
- **Vulnerability Type:** Business Logic Flaw / Session Management
- **Platform:** HackerOne
- **Program:** Localize
- **Bounty:** $500+
- **Description:** A browser cache management and logout vulnerability where logging out of the application did not clear sensitive information from the browser cache. A subsequent user of the same browser could access cached sensitive data.
- **How It Was Found:** Testing the logout flow and checking if sensitive data remained in browser cache, localStorage, sessionStorage, and IndexedDB after logout.
- **Impact:** Information disclosure to subsequent users of shared computers, potential account compromise.
- **Key Takeaway:** Always test what happens after logout. Check: browser cache (Cache-Control headers), localStorage, sessionStorage, IndexedDB, and cookies. Sensitive data should be cleared on logout.
- **Source:** https://hackerone.com/reports/7909

### 7. Price Manipulation via Negative Values
- **Severity:** Critical
- **Vulnerability Type:** Business Logic Flaw / Price Manipulation
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $2,000-$10,000
- **Description:** An attacker manipulated a product's price by tampering with the request, and the application accepted negative values as the price. When the attacker submitted a negative amount, the order was placed and the negative amount was credited to the attacker's account wallet.
- **How It Was Found:** Intercepting checkout/payment requests with Burp Suite and modifying price, quantity, and amount parameters to negative values, zero, or extremely large numbers.
- **Impact:** Direct financial loss - the company would be crediting money to the attacker's wallet instead of charging them.
- **Key Takeaway:** Always test price/amount fields with: negative values, zero, extremely large numbers, decimal precision attacks (0.001), and currency manipulation. Financial platforms often have weak server-side validation.
- **Source:** https://medium.com/armourinfosec/exploiting-business-logic-vulnerabilities-234f97d6c4c0

### 8. Infinite Coupon Exploitation
- **Severity:** High
- **Vulnerability Type:** Business Logic Flaw / Coupon Abuse
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $1,000-$5,000
- **Description:** Attackers found loopholes in business logic to exploit coupon functionalities for "infinite coupons," effectively bypassing payment requirements. The application failed to track coupon usage per user or per transaction.
- **How It Was Found:** Testing coupon application with: the same code multiple times in sequence, concurrent coupon applications via race conditions, and coupon application after partial checkout.
- **Impact:** Complete payment bypass through stacked or reused coupons.
- **Key Takeaway:** Coupon systems should be tested for: reuse, stacking, race conditions, concurrent application, and value manipulation. Use Turbo Intruder for concurrent coupon application testing.
- **Source:** https://medium.com/@illoyscizceneghposter/payment-bypass-guide-for-bug-bounty-69-case-studies-15379b4f76fa

### 9. Payment Bypass - Quantity Manipulation
- **Severity:** Critical
- **Vulnerability Type:** Business Logic Flaw / Payment Bypass
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $2,000-$10,000
- **Description:** By manipulating the quantity parameter in checkout requests to zero or negative values, attackers could bypass payment or receive credits. Some applications calculated the total as price * quantity, and a negative quantity would result in a negative total.
- **How It Was Found:** Modifying quantity values in cart/checkout requests to 0, -1, or very large numbers, and observing the server's calculation behavior.
- **Impact:** Free products or financial credits through payment bypass.
- **Key Takeaway:** Test all mathematical operations in e-commerce: quantity manipulation, price tampering, tax calculation bypass, shipping cost manipulation, and currency conversion exploits.
- **Source:** Referenced in Payment Bypass Guide (69 case studies)

### 10. Gift Card Value Manipulation
- **Severity:** High
- **Vulnerability Type:** Business Logic Flaw
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $1,000-$5,000
- **Description:** Attackers could manipulate gift card values during purchase or redemption. By intercepting the gift card creation or redemption request, the value could be modified to an arbitrary amount, effectively generating unlimited store credit.
- **How It Was Found:** Intercepting gift card purchase/redemption requests and modifying the value parameter.
- **Impact:** Creation of gift cards with arbitrary values, leading to financial loss.
- **Key Takeaway:** Gift card, store credit, and loyalty point systems are high-value business logic targets. Test value creation, transfer, and redemption for manipulation possibilities.
- **Source:** Referenced in bug bounty writeup collections

### 11. Subscription Plan Downgrade Bypass
- **Severity:** Medium
- **Vulnerability Type:** Business Logic Flaw
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $500-$2,000
- **Description:** Users could retain premium features after downgrading their subscription plan. The application only checked the subscription tier during plan change but didn't re-validate permissions for existing feature access.
- **How It Was Found:** Subscribing to a premium plan, using premium features, then downgrading while checking if premium features remained accessible.
- **Impact:** Loss of subscription revenue as users maintain premium access without paying.
- **Key Takeaway:** Test subscription lifecycle: upgrade, downgrade, cancel, and trial expiration. Premium features should be re-validated after any subscription state change.
- **Source:** Referenced in bug bounty writeup collections

### 12. Referral System Abuse
- **Severity:** Medium
- **Vulnerability Type:** Business Logic Flaw
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $500-$2,000
- **Description:** Referral programs could be abused by: self-referring using multiple accounts, referring non-existent accounts, manipulating referral codes, or claiming referral bonuses without the referred user completing required actions.
- **How It Was Found:** Creating multiple accounts and testing the referral flow for: self-referral detection bypass, referral requirement validation, and bonus claim timing.
- **Impact:** Fraudulent referral bonuses, financial loss for the company.
- **Key Takeaway:** Referral systems often have weak anti-abuse controls. Test for: email alias abuse (user+1@gmail.com), referral chain manipulation, and race conditions in referral bonus claiming.
- **Source:** Multiple bug bounty reports

### 13. Free Trial Abuse Through Account Recreation
- **Severity:** Medium
- **Vulnerability Type:** Business Logic Flaw
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $500-$2,000
- **Description:** Users could create unlimited free trial accounts by: using email aliases, different email providers, or by simply re-registering after trial expiration. The application failed to fingerprint users across trial periods.
- **How It Was Found:** Testing trial registration with: email aliases (user+trial1@gmail.com), different emails, and checking if device/browser fingerprinting prevented re-registration.
- **Impact:** Permanent free access to paid services through trial abuse.
- **Key Takeaway:** Trial systems should be tested for: email alias abuse, browser fingerprint bypass, and account recreation after trial expiration. This is a common finding but may be out of scope for some programs.
- **Source:** Multiple bug bounty reports

### 14. Checkout Flow Manipulation - Skipping Steps
- **Severity:** High
- **Vulnerability Type:** Business Logic Flaw
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $1,000-$5,000
- **Description:** Multi-step checkout flows could be manipulated by skipping steps (like payment verification), reordering steps, or directly accessing the order confirmation endpoint without completing payment.
- **How It Was Found:** Mapping the entire checkout flow, then testing if later steps could be accessed directly without completing earlier steps (especially payment).
- **Impact:** Free purchases by bypassing the payment step in the checkout flow.
- **Key Takeaway:** Multi-step workflows (checkout, registration, verification) should be tested for step-skipping. Can you access step 3 directly without completing steps 1 and 2? Are server-side state checks enforced?
- **Source:** Referenced in bug bounty writeup collections

### 15. Vote/Like Manipulation
- **Severity:** Low-Medium
- **Vulnerability Type:** Business Logic Flaw
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $100-$500
- **Description:** Voting and like systems could be manipulated to: cast multiple votes from the same user, remove vote limits, or manipulate vote counts through race conditions. The application relied on client-side enforcement of voting limits.
- **How It Was Found:** Testing voting endpoints for: rate limiting, session-based vote tracking bypass, and concurrent vote submission via race conditions.
- **Impact:** Manipulation of content ranking, unfair competitive advantage in voting systems.
- **Key Takeaway:** Social features (voting, liking, following) are easy business logic targets. While low severity individually, vote manipulation on platforms that use votes for content ranking can have significant business impact.
- **Source:** Multiple bug bounty reports

### 16. Order Status Manipulation
- **Severity:** High
- **Vulnerability Type:** Business Logic Flaw
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $1,000-$5,000
- **Description:** Attackers could manipulate order statuses (e.g., marking an order as "returned" without returning the product, or changing status to "cancelled" to get a refund while keeping the product).
- **How It Was Found:** Testing order management endpoints for unauthorized status transitions.
- **Impact:** Financial fraud through false returns/cancellations.
- **Key Takeaway:** State machine transitions in order management should follow strict rules. Test if you can transition orders to unexpected states: delivered -> returned (without shipping), processing -> cancelled (after shipping).
- **Source:** Referenced in bug bounty writeup collections

### 17. Currency Conversion Exploitation
- **Severity:** High
- **Vulnerability Type:** Business Logic Flaw
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $1,000-$5,000
- **Description:** Currency conversion vulnerabilities where attackers could exploit rounding errors, stale exchange rates, or conversion logic to gain financial advantage. For example, rapidly converting between currencies could generate profit through rounding errors.
- **How It Was Found:** Testing currency-related features for: stale exchange rates, rounding manipulation, and conversion loop exploitation.
- **Impact:** Direct financial gain through currency conversion exploitation.
- **Key Takeaway:** Financial applications with currency conversion should be tested for: rounding direction manipulation, conversion loops (A -> B -> C -> A with profit), and race conditions during rate updates.
- **Source:** Referenced in bug bounty writeup collections

### 18. Invite System Abuse - Unauthorized Team Access
- **Severity:** High
- **Vulnerability Type:** Business Logic Flaw
- **Platform:** HackerOne
- **Program:** Omise
- **Bounty:** $500+
- **Description:** A race condition in the invite user action allowed sending multiple invitations simultaneously, potentially bypassing invitation limits or gaining unauthorized team access.
- **How It Was Found:** Sending concurrent invite requests and testing the invitation flow for race conditions.
- **Impact:** Unauthorized access to team resources and data through invite system abuse.
- **Key Takeaway:** Invitation and user management systems should be tested for: race conditions in invite sending, invitation replay, and privilege escalation through invite role manipulation.
- **Source:** https://hackerone.com/reports/1285538

### 19. Two-for-One Exploit via Cart Manipulation
- **Severity:** High
- **Vulnerability Type:** Business Logic Flaw
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $1,000-$3,000
- **Description:** Cart manipulation where adding an item, proceeding to checkout, then adding another item before payment completion could result in receiving both items for the price of one.
- **How It Was Found:** Testing the timing between cart modification and payment processing, looking for race windows.
- **Impact:** Financial loss through receiving unpaid products.
- **Key Takeaway:** Cart manipulation during checkout is a classic business logic attack. Test: adding items during payment processing, modifying quantities mid-checkout, and changing products after price calculation.
- **Source:** Referenced in bug bounty writeup collections

### 20. Mass Assignment / Parameter Pollution for Role Escalation
- **Severity:** Critical
- **Vulnerability Type:** Business Logic Flaw / Mass Assignment
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $2,000-$10,000
- **Description:** Mass assignment vulnerabilities where including additional parameters in registration or profile update requests could escalate user roles. For example, adding "role=admin" or "isAdmin=true" to a registration request.
- **How It Was Found:** Adding unexpected parameters to registration and profile update requests: role, isAdmin, admin, group, permission, type, privilege.
- **Impact:** Unauthorized privilege escalation to admin or other elevated roles.
- **Key Takeaway:** Always test registration and profile update endpoints with additional parameters that might control user roles or permissions. Use parameter pollution techniques to inject role-related fields.
- **Source:** Multiple bug bounty reports

---

## Additional Reports (Expanded Collection)

### 21. Business Logic Error Leads to Bypass 2FA Requirement (HackerOne)
- **Severity**: High
- **Bounty**: $0 (platform improvement)
- **Program**: HackerOne
- **Platform**: HackerOne
- **Description**: A business logic error allowed bypassing the two-factor authentication requirement on HackerOne. By manipulating the authentication flow, an attacker could access accounts protected by 2FA without providing the second factor.
- **How Found**: Testing the 2FA enforcement flow by accessing protected endpoints directly, skipping the 2FA verification step.
- **Impact**: Complete bypass of 2FA, undermining account security for all users who relied on it.
- **Key Takeaway**: 2FA enforcement should be tested at every protected endpoint, not just the login page. Check if API endpoints enforce 2FA independently.
- **Source**: https://hackerone.com/reports/534524

### 22. Parameter Tampering Leads to Product Price Manipulation (Adobe)
- **Severity**: High
- **Bounty**: $0 (VDP)
- **Program**: Adobe
- **Platform**: HackerOne
- **Description**: Parameter tampering in Adobe's purchase flow allowed manipulation of product prices. By intercepting and modifying the price parameter in the checkout request, an attacker could purchase products at arbitrary prices.
- **How Found**: Intercepting checkout API requests with Burp Suite and modifying price-related parameters before they reached the server.
- **Impact**: Financial loss through purchasing premium software at manipulated prices.
- **Key Takeaway**: Always test price parameters in checkout flows. Even large companies like Adobe can miss server-side price validation.
- **Source**: https://github.com/reddelexc/hackerone-reports/blob/master/tops_by_bug_type/TOPBUSINESSLOGIC.md

### 23. Total Paid Bounty Can Be Manipulated via Program Dashboard (HackerOne)
- **Severity**: Medium
- **Bounty**: $2,500
- **Program**: HackerOne
- **Platform**: HackerOne
- **Description**: A business logic flaw in HackerOne's program dashboard allowed manipulation of the total paid bounty amount displayed. The bounty calculation logic could be exploited to show incorrect totals.
- **How Found**: Analyzing the bounty calculation endpoints and finding inconsistencies in how totals were computed across different views.
- **Impact**: Misrepresentation of program spending, potential impact on program reputation and researcher trust.
- **Key Takeaway**: Dashboard and analytics calculations are often overlooked in security testing. Test if displayed aggregates can be manipulated.
- **Source**: https://hackerone.com/reports/674757

### 24. Ability to Determine Available Bounty Balance of Programs (HackerOne)
- **Severity**: Medium
- **Bounty**: $500
- **Program**: HackerOne
- **Platform**: HackerOne
- **Description**: Through a business logic information disclosure, researchers could determine the exact bounty balance available for specific bug bounty programs, which should have been confidential information.
- **How Found**: Analyzing API responses and finding that certain endpoints leaked financial information about program budgets.
- **Impact**: Information disclosure of confidential financial data about bug bounty programs.
- **Key Takeaway**: API responses should be audited for information leakage. Financial data like budget amounts should never be exposed to unauthorized users.
- **Source**: https://hackerone.com/reports/293593

### 25. Free Ride via Payment Profile UUID Manipulation (Uber)
- **Severity**: Critical
- **Bounty**: $5,000+
- **Program**: Uber
- **Platform**: HackerOne
- **Description**: By changing the paymentProfileUuid parameter when booking a ride, an attacker could use another user's payment method or bypass payment entirely, resulting in free rides.
- **How Found**: Intercepting the ride booking request and modifying the payment profile identifier to reference other users' payment methods.
- **Impact**: Direct financial fraud through free rides charged to other users or bypassing payment entirely.
- **Key Takeaway**: Payment profile references (UUIDs, IDs) should always be validated against the authenticated user. IDOR in payment contexts is critical severity.
- **Source**: https://medium.com/infosecmatrix/how-to-exploit-business-logic-vulnerabilities-for-bug-bounty-2024-5c9f14420d50

### 26. Payment Gateway Status Manipulation (Shopify)
- **Severity**: High
- **Bounty**: $500+
- **Program**: Shopify
- **Platform**: HackerOne
- **Description**: A third-party payment gateway used with Shopify did not offer secure means of reporting transaction status. An attacker could modify the transaction status displayed to the merchant, making unpaid orders appear as paid.
- **How Found**: Analyzing the payment callback mechanism between the third-party gateway and Shopify, finding that transaction status was not cryptographically verified.
- **Impact**: Merchants could ship products for orders that were never actually paid, causing financial loss.
- **Key Takeaway**: Payment gateway integrations are a rich attack surface. Test the callback/webhook mechanism for status manipulation and replay attacks.
- **Source**: https://hackerone.com/reports/56628

### 27. Email Confirmation Bypass Leading to Full Privilege Escalation (Shopify)
- **Severity**: Critical
- **Bounty**: $15,250
- **Program**: Shopify
- **Platform**: HackerOne
- **Description**: An email confirmation bypass in myshop.myshopify.com allowed full privilege escalation to any shop owner. By manipulating the email verification flow, an attacker could take over any Shopify store.
- **How Found**: Testing the email confirmation flow for bypass techniques, including token manipulation and step-skipping in the verification process.
- **Impact**: Complete takeover of any Shopify store, including access to financial data, customer information, and store management.
- **Key Takeaway**: Email verification flows are critical business logic targets. Test for: token reuse, token prediction, step skipping, and race conditions in verification.
- **Source**: https://github.com/reddelexc/hackerone-reports/blob/master/tops_by_program/TOPSHOPIFY.md

### 28. Partner Email Confirmation Bypass to Store Takeover (Shopify)
- **Severity**: Critical
- **Bounty**: $15,250
- **Program**: Shopify
- **Platform**: HackerOne
- **Description**: An ability to bypass partner email confirmation allowed takeover of any store given an employee email address. The partner verification process had a logic flaw that accepted unverified partner accounts.
- **How Found**: Analyzing the partner invitation and verification flow, finding that certain steps could be bypassed to gain store access without proper authorization.
- **Impact**: Full store takeover through partner access escalation, affecting any Shopify store.
- **Key Takeaway**: Multi-party authorization flows (partner/employee/admin) are complex and prone to logic errors. Test each role's verification independently.
- **Source**: https://github.com/reddelexc/hackerone-reports/blob/master/tops_by_program/TOPSHOPIFY.md

### 29. Coinbase Ethereum Account Balance Manipulation
- **Severity**: Critical
- **Bounty**: $10,000+
- **Program**: Coinbase
- **Platform**: HackerOne
- **Description**: A business logic vulnerability in Coinbase allowed manipulation of Ethereum account balances. The flaw in the balance tracking system could be exploited to credit accounts with unauthorized funds.
- **How Found**: Testing the deposit and withdrawal flows for inconsistencies in balance tracking, particularly during concurrent or edge-case transactions.
- **Impact**: Direct financial theft through balance manipulation on a major cryptocurrency exchange.
- **Key Takeaway**: Cryptocurrency exchanges handle immutable transactions but often have mutable internal ledgers. Test internal balance tracking for manipulation.
- **Source**: https://github.com/reddelexc/hackerone-reports/blob/master/tops_by_program/TOPCOINBASE.md

### 30. Facebook Business Account Data Source Access via IDOR in GraphQL
- **Severity**: High
- **Bounty**: $4,500
- **Program**: Facebook (Meta)
- **Platform**: Facebook Bug Bounty
- **Description**: An IDOR vulnerability in Facebook's GraphQL API allowed accessing data sources of any Facebook Business account. By manipulating the business account ID in GraphQL queries, an attacker could read sensitive business data.
- **How Found**: Testing GraphQL queries with different business account IDs to check for authorization enforcement on data source access.
- **Impact**: Unauthorized access to any Facebook Business account's data sources, including analytics and advertising data.
- **Key Takeaway**: GraphQL APIs often have weaker authorization checks than REST APIs. Test every query and mutation with different user contexts and object IDs.
- **Source**: https://github.com/jaiswalakshansh/Facebook-BugBounty-Writeups

### 31. Exposing Primary Facebook Email Address
- **Severity**: Medium
- **Bounty**: $4,500
- **Program**: Facebook (Meta)
- **Platform**: Facebook Bug Bounty
- **Description**: A business logic flaw in Facebook allowed exposing any user's primary email address, even when the user had set it to private. The information disclosure occurred through an unprotected API endpoint.
- **How Found**: Enumerating Facebook API endpoints and finding one that returned email addresses regardless of privacy settings.
- **Impact**: Mass email harvesting of Facebook users, enabling phishing and social engineering attacks.
- **Key Takeaway**: Privacy settings should be enforced at the API level, not just the UI level. Test if private information is accessible through alternative API endpoints.
- **Source**: https://github.com/jaiswalakshansh/Facebook-BugBounty-Writeups

### 32. GitLab Project Template Copies Private Project Data
- **Severity**: Critical
- **Bounty**: $12,000
- **Program**: GitLab
- **Platform**: HackerOne
- **Description**: The GitLab Project Template functionality allowed copying private project data including repository contents, confidential issues, snippets, and merge requests. An attacker could access any private project's data by using it as a template.
- **How Found**: Testing the project template feature with references to private projects that the user should not have access to.
- **Impact**: Complete data exfiltration from any private GitLab project, including source code and confidential issues.
- **Key Takeaway**: Template and copy features often bypass access controls. When data is duplicated or referenced, authorization checks may be missing on the source.
- **Source**: https://github.com/reddelexc/hackerone-reports/blob/master/tops_100/TOP100PAID.md

### 33. HackerOne Customer Report Visibility Manipulation
- **Severity**: Medium
- **Bounty**: $500+
- **Program**: HackerOne
- **Platform**: HackerOne
- **Description**: A business logic flaw allowed manipulation of report visibility settings on HackerOne, potentially exposing confidential vulnerability reports to unauthorized parties.
- **How Found**: Testing report visibility controls and finding that certain state transitions could be manipulated to change report access.
- **Impact**: Unauthorized disclosure of confidential vulnerability information.
- **Key Takeaway**: Visibility and access control state machines should be tested for unauthorized transitions. Can a report be moved from private to public without proper authorization?
- **Source**: https://hackerone.com/reports/378122

### 34. Payment Bypass via Delivery Charge Manipulation (BigBasket)
- **Severity**: High
- **Bounty**: $500+
- **Program**: BigBasket
- **Platform**: Direct
- **Description**: A payment amount manipulation vulnerability on BigBasket allowed purchasing products without paying for delivery charges and one-time membership fees. The delivery fee calculation was performed client-side.
- **How Found**: Intercepting the checkout request and modifying the delivery charge and membership fee parameters to zero.
- **Impact**: Free delivery and membership access, resulting in revenue loss for the platform.
- **Key Takeaway**: All fee calculations (delivery, service fees, taxes, membership) should be validated server-side. Test each line item in the order total for manipulation.
- **Source**: https://medium.com/@ranjeetjagtap25/payment-bypass-vulnerability-on-bigbasket-2aab137e9631

### 35. Bypassing Withdrawal Limits on Financial Platform
- **Severity**: Critical
- **Bounty**: $5,000-$15,000
- **Program**: Multiple Financial Platforms
- **Platform**: Various
- **Description**: Withdrawal limit bypasses where concurrent or carefully timed withdrawal requests could exceed daily/weekly withdrawal limits. The limit enforcement used application-level checks that were not atomic.
- **How Found**: Sending multiple withdrawal requests simultaneously or in rapid succession to test if the withdrawal limit was enforced atomically.
- **Impact**: Unauthorized fund extraction beyond permitted limits.
- **Key Takeaway**: Financial limits (withdrawal, transfer, purchase) should be enforced at the database level with atomic operations, not application-level checks.
- **Source**: Multiple bug bounty reports

### 36. Abuse of Promotional Credit System
- **Severity**: High
- **Bounty**: $2,000-$5,000
- **Program**: Multiple (Ride-sharing, Food Delivery)
- **Platform**: Various
- **Description**: Promotional credit systems could be abused by creating multiple accounts with different email aliases, each receiving sign-up bonuses. The platform did not fingerprint users across accounts to prevent abuse.
- **How Found**: Creating accounts with email aliases (user+1@gmail.com, user+2@gmail.com) and testing if each received the full promotional credit.
- **Impact**: Unlimited promotional credits through systematic account creation.
- **Key Takeaway**: Promotional credit systems should be tested with email aliases, VPN/proxy usage, and device fingerprint manipulation to check for abuse prevention.
- **Source**: Multiple bug bounty reports

### 37. Bypassing KYC Verification Requirements
- **Severity**: High
- **Bounty**: $2,000-$10,000
- **Program**: Multiple (Financial, Crypto)
- **Platform**: Various
- **Description**: KYC (Know Your Customer) verification could be bypassed by manipulating the verification state in the API, allowing users to access features that required identity verification without completing it.
- **How Found**: Mapping the KYC verification flow and testing if protected features checked the verification status server-side or only relied on frontend enforcement.
- **Impact**: Unauthorized access to financial services without identity verification, enabling money laundering and fraud.
- **Key Takeaway**: KYC enforcement should be checked at every protected endpoint. Test if changing the verification status parameter in requests bypasses checks.
- **Source**: Multiple bug bounty reports

### 38. Auction System Bid Manipulation
- **Severity**: High
- **Bounty**: $1,000-$5,000
- **Program**: Multiple (Auction/Marketplace)
- **Platform**: Various
- **Description**: Auction systems where bids could be manipulated after placement, retracted after winning, or where shill bidding detection was absent. The auction state machine did not properly enforce bid finality.
- **How Found**: Testing bid modification/retraction endpoints after auction close, and testing if bidding against yourself was prevented.
- **Impact**: Financial manipulation of auction outcomes, unfair bidding practices.
- **Key Takeaway**: Auction and bidding systems have complex state machines. Test: bid retraction timing, self-bidding, bid amount modification, and auction extension manipulation.
- **Source**: Multiple bug bounty reports

### 39. Bypassing Rate Limits on Password Reset to Enable Brute Force
- **Severity**: High
- **Bounty**: $1,000-$3,000
- **Program**: Multiple
- **Platform**: Various
- **Description**: Password reset token validation lacked proper rate limiting, allowing brute force of short numeric reset codes. The rate limit was enforced per IP but could be bypassed using headers like X-Forwarded-For.
- **How Found**: Testing password reset endpoints for rate limiting and trying bypass techniques: IP rotation, X-Forwarded-For header manipulation, and concurrent requests.
- **Impact**: Account takeover through brute-forced password reset tokens.
- **Key Takeaway**: Password reset tokens should be long enough to prevent brute force (at least 20+ random characters). Short numeric codes (4-6 digits) require strict rate limiting.
- **Source**: Multiple bug bounty reports

### 40. Shipping Address Modification After Payment
- **Severity**: Medium
- **Bounty**: $500-$2,000
- **Program**: Multiple (E-commerce)
- **Platform**: Various
- **Description**: After completing payment, an attacker could modify the shipping address to redirect deliveries. The order management system did not lock the shipping address after payment confirmation.
- **How Found**: Attempting to modify order details (especially shipping address) via API after the payment was confirmed but before shipping.
- **Impact**: Package theft by redirecting deliveries to attacker-controlled addresses.
- **Key Takeaway**: Order details should be immutable after payment. Test if any order attributes can be modified post-payment through API calls.
- **Source**: Multiple bug bounty reports

### 41. Bypassing Account Deletion Cooling Period
- **Severity**: Medium
- **Bounty**: $500-$1,000
- **Program**: Multiple
- **Platform**: Various
- **Description**: Account deletion cooling periods (e.g., 30-day wait before permanent deletion) could be bypassed by manipulating the deletion timestamp or directly calling the permanent deletion endpoint.
- **How Found**: Testing the account deletion flow by modifying deletion-related parameters or directly accessing the final deletion endpoint.
- **Impact**: Immediate and irreversible account destruction, potentially used in targeted attacks after temporary account access.
- **Key Takeaway**: Time-based security controls should be enforced server-side. Test if cooling periods can be bypassed by direct API calls or timestamp manipulation.
- **Source**: Multiple bug bounty reports

### 42. Reward Points Multiplication via Decimal Precision Exploit
- **Severity**: High
- **Bounty**: $1,000-$5,000
- **Program**: Multiple (Loyalty Programs)
- **Platform**: Various
- **Description**: Loyalty point calculations using floating-point arithmetic could be exploited through precision manipulation. By making many small transactions with carefully chosen amounts, rounding errors accumulated to generate extra points.
- **How Found**: Testing point calculations with amounts that produce rounding edges (e.g., $0.005 transactions where the point calculation rounds up).
- **Impact**: Generating unlimited loyalty points through accumulated rounding errors.
- **Key Takeaway**: Financial and point calculations should use integer arithmetic (cents, not dollars). Test calculations at rounding boundaries for accumulation exploits.
- **Source**: Multiple bug bounty reports

### 43. API Versioning Authorization Bypass
- **Severity**: High
- **Bounty**: $2,000-$5,000
- **Program**: Multiple
- **Platform**: Various
- **Description**: Older API versions (v1, v2) lacked authorization checks that were added in newer versions (v3). By calling deprecated but still-active API endpoints, attackers could bypass access controls.
- **How Found**: Discovering API version endpoints through documentation, JavaScript source analysis, or URL fuzzing, then comparing authorization enforcement across versions.
- **Impact**: Complete authorization bypass through legacy API endpoints.
- **Key Takeaway**: Always test for older API versions. Many companies add security to new API versions but leave old versions running. Try /api/v1/, /api/v2/ when testing /api/v3/.
- **Source**: Multiple bug bounty reports

### 44. Bypassing Two-User Approval Requirement
- **Severity**: High
- **Bounty**: $2,000-$5,000
- **Program**: Multiple (Financial/Enterprise)
- **Platform**: Various
- **Description**: Dual-approval (maker-checker) controls for sensitive operations could be bypassed by a single user. The approval system checked for two approvals but not that they came from different users.
- **How Found**: Approving the same action twice from the same account, or creating a second session to approve an action initiated by the same user.
- **Impact**: Single-user execution of operations that require dual approval, bypassing financial controls.
- **Key Takeaway**: Maker-checker patterns should verify that approvals come from distinct users. Test if the same user can both initiate and approve sensitive operations.
- **Source**: Multiple bug bounty reports

### 45. E-commerce Tax Calculation Bypass
- **Severity**: Medium
- **Bounty**: $500-$2,000
- **Program**: Multiple (E-commerce)
- **Platform**: Various
- **Description**: Tax calculations could be bypassed by manipulating the shipping address to a tax-free jurisdiction after the tax calculation step but before final order submission.
- **How Found**: Changing the shipping address between the tax calculation step and the order finalization step in a multi-step checkout.
- **Impact**: Tax evasion through address manipulation during checkout.
- **Key Takeaway**: Multi-step checkout flows should recalculate all financial values (price, tax, shipping) at each step. Test if values from earlier steps are trusted without re-validation.
- **Source**: Multiple bug bounty reports

### 46. Manipulating Review/Rating Timestamps
- **Severity**: Low-Medium
- **Bounty**: $200-$500
- **Program**: Multiple (Marketplace/Review)
- **Platform**: Various
- **Description**: Product review systems allowed manipulation of review timestamps, enabling backdating reviews to appear as early/verified purchasers, or posting reviews for products not yet purchased.
- **How Found**: Modifying the timestamp or purchase verification parameters in review submission requests.
- **Impact**: Manipulation of product ratings and trust signals, affecting consumer purchasing decisions.
- **Key Takeaway**: Review systems should enforce purchase verification server-side and use server-generated timestamps. Test if review parameters can be tampered with.
- **Source**: Multiple bug bounty reports

### 47. Exploiting Abandoned Cart Discount Logic
- **Severity**: Medium
- **Bounty**: $500-$1,000
- **Program**: Multiple (E-commerce)
- **Platform**: Various
- **Description**: Abandoned cart discount systems that automatically send discount codes after cart abandonment could be exploited by deliberately abandoning carts to trigger discount generation, then using the codes for purchases.
- **How Found**: Adding items to cart, waiting for the abandonment trigger, collecting the discount code, and repeating the process.
- **Impact**: Systematic discount harvesting, reducing the merchant's revenue.
- **Key Takeaway**: Automated marketing/discount systems (abandoned cart, re-engagement) should have abuse detection. Test if discount triggers can be systematically activated.
- **Source**: Multiple bug bounty reports

### 48. Subscription Cancellation Refund Manipulation
- **Severity**: High
- **Bounty**: $1,000-$5,000
- **Program**: Multiple (SaaS)
- **Platform**: Various
- **Description**: Subscription cancellation and refund flows could be manipulated to receive refunds while retaining access. By cancelling and re-subscribing in rapid succession, or by manipulating the cancellation date, users could get prorated refunds incorrectly.
- **How Found**: Testing subscription lifecycle operations (cancel, refund, resubscribe) in various sequences and timing patterns.
- **Impact**: Financial loss through fraudulent refunds while maintaining service access.
- **Key Takeaway**: Subscription state machines are complex. Test all transitions: subscribe -> cancel -> refund -> resubscribe. Check if proration calculations can be manipulated.
- **Source**: Multiple bug bounty reports

### 49. Bypassing Geographic Restrictions via API
- **Severity**: Medium
- **Bounty**: $500-$2,000
- **Program**: Multiple (Streaming/Financial)
- **Platform**: Various
- **Description**: Geographic restrictions enforced at the CDN or frontend level could be bypassed by directly calling backend API endpoints, which did not independently verify the user's location.
- **How Found**: Identifying the backend API endpoints through JavaScript analysis or traffic interception, then calling them directly while bypassing the geo-restriction layer.
- **Impact**: Accessing geographically restricted content or services from unauthorized regions.
- **Key Takeaway**: Geographic restrictions must be enforced at every layer, not just the CDN/frontend. Test if direct API calls bypass geo-fencing.
- **Source**: Multiple bug bounty reports

### 50. Multi-Currency Arbitrage in Digital Marketplace
- **Severity**: High
- **Bounty**: $3,000-$10,000
- **Program**: Multiple (Digital Marketplace)
- **Platform**: Various
- **Description**: Digital marketplaces supporting multiple currencies had price discrepancies between currency versions. By purchasing in the cheaper currency and selling/transferring in the more expensive currency, attackers could profit from the arbitrage.
- **How Found**: Comparing product prices across different currency settings and testing if purchases in one currency could be consumed/transferred in another.
- **Impact**: Direct financial gain through currency arbitrage exploitation.
- **Key Takeaway**: Multi-currency platforms should lock the currency at purchase time and prevent cross-currency transfers. Test currency switching during transactions.
- **Source**: Multiple bug bounty reports

### 51. Invitation Link Reuse After Acceptance
- **Severity**: Medium
- **Bounty**: $500-$1,500
- **Program**: Multiple (Collaboration)
- **Platform**: Various
- **Description**: Team/organization invitation links remained valid even after being accepted. An attacker who obtained a used invitation link could use it to add additional unauthorized users or create duplicate memberships.
- **How Found**: Testing invitation links after they had been accepted to check if they could be reused by different accounts.
- **Impact**: Unauthorized team access through invitation link reuse.
- **Key Takeaway**: Single-use tokens should be invalidated immediately after use. Test all invitation and activation links for reuse after acceptance.
- **Source**: Multiple bug bounty reports

### 52. Draft Order Price Modification (Shopify)
- **Severity**: High
- **Bounty**: $2,000+
- **Program**: Shopify
- **Platform**: HackerOne
- **Description**: Draft orders in Shopify could be modified after creation to change product prices before the customer completed payment. The draft order API did not properly lock prices after the order link was shared.
- **How Found**: Creating a draft order, sharing the payment link, then modifying the order's price via API before the customer paid.
- **Impact**: Selling products at incorrect prices, either overcharging customers or undercharging to defraud the merchant.
- **Key Takeaway**: Draft/pending orders should lock financial details once shared. Test if order modifications are possible between creation and payment.
- **Source**: Referenced in Shopify HackerOne disclosures

### 53. Exploiting Bulk Import/Export for Data Exfiltration
- **Severity**: High
- **Bounty**: $2,000-$5,000
- **Program**: Multiple (Enterprise SaaS)
- **Platform**: Various
- **Description**: Bulk data export features intended for administrators could be accessed by lower-privileged users through direct API calls. The authorization check was only on the UI, not the export endpoint.
- **How Found**: Discovering export endpoint URLs through JavaScript analysis and calling them with a low-privilege session token.
- **Impact**: Mass data exfiltration of customer data, financial records, or other sensitive information.
- **Key Takeaway**: Data export endpoints are high-value targets. Test if export/download endpoints enforce the same authorization as the UI that triggers them.
- **Source**: Multiple bug bounty reports

### 54. Webhook URL Manipulation for SSRF
- **Severity**: High
- **Bounty**: $2,000-$5,000
- **Program**: Multiple
- **Platform**: Various
- **Description**: Webhook configuration features allowed setting internal URLs (127.0.0.1, metadata endpoints) as webhook targets, enabling SSRF through the webhook delivery mechanism.
- **How Found**: Configuring webhooks with internal IP addresses and cloud metadata URLs to test for SSRF through the webhook system.
- **Impact**: Access to internal services and cloud metadata, potentially leading to credential theft and lateral movement.
- **Key Takeaway**: Webhook URLs should be validated against SSRF. Test with: internal IPs, cloud metadata URLs (169.254.169.254), and DNS rebinding techniques.
- **Source**: Multiple bug bounty reports

### 55. Bypassing Feature Flags via Direct API Access
- **Severity**: Medium
- **Bounty**: $500-$2,000
- **Program**: Multiple
- **Platform**: Various
- **Description**: Features gated behind feature flags (not yet released) could be accessed by directly calling their API endpoints. The feature flag only controlled UI visibility, not API availability.
- **How Found**: Discovering unreleased feature endpoints through JavaScript bundle analysis, API documentation, or mobile app reverse engineering.
- **Impact**: Access to unreleased features that may have security vulnerabilities due to incomplete development.
- **Key Takeaway**: Feature flags should gate both UI and API access. Unreleased features accessible via API may have unpatched vulnerabilities.
- **Source**: Multiple bug bounty reports

---

## Business Logic Testing Methodology Summary

### Key Areas to Test
1. **Payment/Checkout flows** - Price manipulation, coupon abuse, step skipping
2. **Subscription management** - Plan upgrade/downgrade abuse
3. **Referral/Loyalty programs** - Self-referral, point manipulation
4. **Access control** - Premium feature bypass, role manipulation
5. **Quantity/Amount fields** - Negative values, zero, overflow
6. **State transitions** - Order status manipulation
7. **Rate limiting** - Vote manipulation, brute force
8. **Currency operations** - Conversion rounding, stale rates
9. **Multi-step workflows** - Step skipping, reordering
10. **Time-based logic** - Trial abuse, expiration bypass

### Testing Approach
1. Map all business workflows end-to-end
2. Identify trust assumptions (what does the app assume users will do?)
3. Test edge cases: zero, negative, empty, extremely large values
4. Test workflow ordering: skip steps, reverse order, repeat steps
5. Test concurrent operations: race conditions in financial transactions
6. Compare UI restrictions vs API enforcement
7. Test with different user roles and subscription levels
