# IDOR / Broken Access Control Bug Bounty Reports

> A collection of accepted/disclosed IDOR (Insecure Direct Object Reference) and Broken Access Control vulnerability reports from bug bounty programs.

---

### 1. IDOR on /bugs.json Enables Viewing Private Report Details (HackerOne)
- **Severity:** Critical
- **Vulnerability Type:** IDOR
- **Platform:** HackerOne
- **Program:** HackerOne
- **Bounty:** $12,500
- **Description:** Any private reports could be accessed by sending a POST request to the `/bugs.json` endpoint with an `organization_id` and `text_query` parameter to search for report IDs. This allowed unauthorized access to confidential vulnerability reports.
- **How It Was Found:** Testing API endpoints with different parameters and observing that the endpoint did not properly verify authorization for the requesting user.
- **Impact:** Access to all private vulnerability reports on HackerOne, including unpatched zero-days and sensitive security information.
- **Key Takeaway:** API endpoints that accept object IDs should always be tested with IDs belonging to other users/organizations. JSON API endpoints often have weaker access controls than their web UI counterparts.
- **Source:** https://hackerone.com/reports/663431

### 2. IDOR on HackerOne Certification System - Delete All Licenses
- **Severity:** Critical
- **Vulnerability Type:** IDOR
- **Platform:** HackerOne
- **Program:** HackerOne
- **Bounty:** $12,500
- **Description:** A critical IDOR vulnerability on HackerOne's certification system allowed deletion of all licenses and certifications from any user's account using a GraphQL query. By changing the user ID in the mutation, an attacker could target any user.
- **How It Was Found:** Testing GraphQL mutations with modified user IDs and object references.
- **Impact:** Ability to delete certifications from any HackerOne user's profile, potentially affecting their reputation and program eligibility.
- **Key Takeaway:** GraphQL APIs are particularly prone to IDOR because they often expose granular operations. Test all GraphQL mutations with different user/object IDs.
- **Source:** https://hackerone.com/reports/2487889

### 3. IDOR to Order, Book, Buy, Reserve on Behalf of Other Users (Yelp)
- **Severity:** High
- **Vulnerability Type:** IDOR
- **Platform:** HackerOne
- **Program:** Yelp
- **Bounty:** $1,000+
- **Description:** An IDOR vulnerability allowed attackers to place orders, make bookings, purchases, and reservations on behalf of other Yelp users by manipulating user identifiers in requests.
- **How It Was Found:** Intercepting and modifying booking/ordering requests to replace the user ID with another user's ID.
- **Impact:** Financial impact on victims through unauthorized orders and reservations, plus privacy violation.
- **Key Takeaway:** E-commerce and booking features are prime IDOR targets. Test all transaction-related endpoints by changing user/account identifiers.
- **Source:** https://hackerone.com/reports/391092

### 4. Vimeo IDOR - Password Reset and Account Takeover
- **Severity:** Critical
- **Vulnerability Type:** IDOR leading to Account Takeover
- **Platform:** HackerOne
- **Program:** Vimeo
- **Bounty:** $5,000+
- **Description:** An IDOR vulnerability allowed attackers to reset any Vimeo user's password and take control of any account. The password reset functionality did not properly validate the requesting user's authorization.
- **How It Was Found:** Testing password reset endpoints with different user IDs and email addresses.
- **Impact:** Full account takeover of any Vimeo user account.
- **Key Takeaway:** Password reset and account recovery features are critical IDOR targets. Always test these flows by manipulating user identifiers.
- **Source:** https://hackerone.com/reports/42587

### 5. IDOR when Editing Email Leads to Account Takeover (Automattic/CrowdSignal)
- **Severity:** Critical
- **Vulnerability Type:** IDOR to Account Takeover
- **Platform:** HackerOne
- **Program:** Automattic
- **Bounty:** $0 (recognized)
- **Description:** An IDOR vulnerability when editing user email addresses at CrowdSignal (Automattic) could lead to account takeover without user interaction. By changing another user's email address, the attacker could then perform password reset.
- **How It Was Found:** Testing email update functionality by modifying the target user ID in the request.
- **Impact:** Full account takeover of any CrowdSignal user without victim interaction.
- **Key Takeaway:** Email change functionality is a high-impact IDOR vector because it can be chained with password reset for full account takeover.
- **Source:** https://hackerone.com/reports/950881

### 6. IDOR on GraphQL Queries (Shopify)
- **Severity:** High
- **Vulnerability Type:** IDOR
- **Platform:** HackerOne
- **Program:** Shopify
- **Bounty:** $5,000
- **Description:** An IDOR vulnerability in Shopify's GraphQL API allowed unauthorized access to shop information and data through manipulated query parameters.
- **How It Was Found:** Testing GraphQL queries with different shop/object IDs to access data belonging to other merchants.
- **Impact:** Access to other Shopify merchants' shop data and potentially sensitive business information.
- **Key Takeaway:** GraphQL introspection can reveal hidden queries and mutations. Use tools like GraphQL Voyager or InQL to map out all available operations, then test each for IDOR.
- **Source:** Referenced in Shopify HackerOne disclosures

### 7. IDOR - User with Manage Apps Permission Gets Shop Info (Shopify Partners)
- **Severity:** Medium
- **Vulnerability Type:** IDOR / Privilege Escalation
- **Platform:** HackerOne
- **Program:** Shopify
- **Bounty:** $1,000+
- **Description:** On partners.shopify.com, a user with only "Manage apps" permission was able to access shop information and staff names from inside the shop, exceeding their intended access level.
- **How It Was Found:** Testing the boundaries of limited permissions by accessing API endpoints meant for higher-privilege users.
- **Impact:** Information disclosure of shop data and staff details to users who should not have access.
- **Key Takeaway:** Permission-based IDOR testing is crucial. Create multiple accounts with different privilege levels and test if lower-privilege accounts can access higher-privilege endpoints.
- **Source:** Referenced in HackerOne Shopify IDOR disclosures

### 8. IDOR to Cancel Table Bookings and Leak Sensitive Info
- **Severity:** High
- **Vulnerability Type:** IDOR
- **Platform:** HackerOne
- **Program:** Undisclosed
- **Bounty:** $1,000+
- **Description:** An IDOR vulnerability allowed canceling any user's table booking and leaking sensitive information including email, mobile number, and UUID of other users.
- **How It Was Found:** Intercepting booking cancellation requests and changing the booking ID to target other users' reservations.
- **Impact:** Business disruption through unauthorized booking cancellation plus PII exposure.
- **Key Takeaway:** Booking/reservation systems often use sequential or predictable IDs. Test cancellation and modification endpoints by changing object IDs.
- **Source:** Referenced in IDOR writeup collections

### 9. IDOR - Delete Other User's Signature (Open-Xchange)
- **Severity:** Medium
- **Vulnerability Type:** IDOR
- **Platform:** HackerOne
- **Program:** Open-Xchange
- **Bounty:** $500+
- **Description:** An IDOR vulnerability in the /appsuite/api/snippet?action=update endpoint allowed deleting other users' email signatures. Although an error was thrown, the deletion was still processed.
- **How It Was Found:** Testing the signature update/delete API with different user IDs, noticing that even error responses resulted in the action being performed.
- **Impact:** Ability to delete email signatures of other users, causing business disruption.
- **Key Takeaway:** Don't assume an error response means the action failed. Always verify the state of the target object after receiving errors - the action may have been partially or fully executed.
- **Source:** Referenced in HackerOne IDOR disclosures

### 10. IDOR to Account Takeover (U.S. Department of Defense)
- **Severity:** Critical
- **Vulnerability Type:** IDOR to Account Takeover
- **Platform:** HackerOne
- **Program:** U.S. Department of Defense
- **Bounty:** N/A (VDP)
- **Description:** An IDOR vulnerability on a DoD web application led to full account takeover. The vulnerability allowed manipulation of user identifiers to access and control other accounts.
- **How It Was Found:** Testing authenticated endpoints by modifying user identifiers in requests.
- **Impact:** Full account takeover on a Department of Defense system.
- **Key Takeaway:** Government VDP programs are excellent targets for IDOR because they often use legacy systems with weaker access controls.
- **Source:** https://hackerone.com/reports/969223

### 11. Full Account Takeover via IDOR (U.S. Department of Defense)
- **Severity:** Critical
- **Vulnerability Type:** IDOR / Account Takeover
- **Platform:** HackerOne
- **Program:** U.S. Department of Defense
- **Bounty:** N/A (VDP)
- **Description:** A full account takeover vulnerability was found through an IDOR, allowing an attacker to access and control any user account on the affected DoD system.
- **How It Was Found:** Systematic testing of user management endpoints with different user IDs.
- **Impact:** Complete compromise of user accounts on a DoD system.
- **Key Takeaway:** Account takeover chains (IDOR -> email change -> password reset) are extremely high-impact and often rated Critical.
- **Source:** https://hackerone.com/reports/847452

### 12. IDOR Leads to Account Takeover (MTN Group)
- **Severity:** Critical
- **Vulnerability Type:** IDOR to Account Takeover
- **Platform:** HackerOne
- **Program:** MTN Group
- **Bounty:** $500+
- **Description:** An IDOR vulnerability in MTN Group's platform led to account takeover, allowing attackers to access and control other users' accounts.
- **How It Was Found:** Testing user account endpoints by manipulating user identifiers.
- **Impact:** Full account takeover of MTN users, potential access to telecommunications accounts and billing information.
- **Key Takeaway:** Telecommunications companies handle sensitive subscriber data. IDOR on telco platforms can expose call records, billing information, and account controls.
- **Source:** https://hackerone.com/reports/1272478

### 13. IDOR Insert/Delete Comments as Another User (Rockstar/Social Club)
- **Severity:** High
- **Vulnerability Type:** IDOR
- **Platform:** HackerOne
- **Program:** Rockstar Games
- **Bounty:** $1,000+
- **Description:** A critical IDOR vulnerability in Social Club allowed attackers to insert and delete comments as another user and also disclosed sensitive information about user accounts.
- **How It Was Found:** Testing comment creation and deletion APIs by modifying user IDs in requests.
- **Impact:** Impersonation through comment manipulation plus information disclosure.
- **Key Takeaway:** Social features (comments, posts, messages) are common IDOR targets. Test all CRUD operations (Create, Read, Update, Delete) for authorization checks.
- **Source:** Referenced in HackerOne IDOR disclosures

### 14. IDOR on User Link Modification (Reddit)
- **Severity:** High
- **Vulnerability Type:** IDOR
- **Platform:** HackerOne
- **Program:** Reddit
- **Bounty:** $5,000
- **Description:** An IDOR vulnerability allowed modification of user links on Reddit, enabling an attacker to change links associated with another user's account.
- **How It Was Found:** Testing user profile modification endpoints with different user identifiers.
- **Impact:** Ability to modify other Reddit users' profile links, potential for phishing or reputation damage.
- **Key Takeaway:** Profile modification endpoints are often tested for XSS but IDOR in profile updates is equally important to test.
- **Source:** Referenced in HackerOne Reddit disclosures

### 15. Broken Access Control - Viewing Other Users' Support Tickets (Fintech)
- **Severity:** Critical
- **Vulnerability Type:** IDOR / Broken Access Control
- **Platform:** HackerOne
- **Program:** Private Fintech Program
- **Bounty:** $5,000
- **Description:** A critical broken access control vulnerability on a banking/fintech platform allowed viewing support requests submitted by other users by simply changing the ticket ID. The endpoint did not verify user ownership of tickets.
- **How It Was Found:** Intercepting support ticket viewing requests and incrementing/modifying the ticket ID parameter.
- **Impact:** Access to other users' support tickets containing sensitive banking information, PII, and potentially financial details.
- **Key Takeaway:** Support ticket systems are goldmines for IDOR because they contain rich user data. Sequential ticket IDs make enumeration trivial.
- **Source:** https://www.webasha.com/blog/what-is-a-real-hackerone-broken-access-control-exploit-worth-5000-full-writeup-inside

### 16. IDOR - First P1 in Bug Bounty (InfoSec Writeups)
- **Severity:** Critical (P1)
- **Vulnerability Type:** IDOR
- **Platform:** Various
- **Program:** Undisclosed
- **Bounty:** Significant
- **Description:** A researcher documented their first P1 (Critical) finding in bug bounty through an IDOR vulnerability. The IDOR allowed access to sensitive user data by manipulating object references in API calls.
- **How It Was Found:** Systematic testing of API endpoints with modified object IDs, using two accounts to verify unauthorized access.
- **Impact:** Complete access to other users' data and account details.
- **Key Takeaway:** IDOR is one of the most accessible vulnerability types for beginners. Create two test accounts and swap identifiers between them to quickly verify IDOR.
- **Source:** https://infosecwriteups.com/idor-insecure-direct-object-references-my-first-p1-in-bugbounty-fb01f50e25df

### 17. IDOR via User Profile Modification (HackerOne Blog)
- **Severity:** High
- **Vulnerability Type:** IDOR
- **Platform:** HackerOne
- **Program:** Undisclosed
- **Bounty:** $2,000+
- **Description:** A researcher identified an IDOR vulnerability that allowed modification of user profiles by changing the user ID parameter, documented in HackerOne's official blog about IDOR impacts.
- **How It Was Found:** Testing profile update endpoints with modified user identifiers.
- **Impact:** Unauthorized modification of other users' profile data.
- **Key Takeaway:** HackerOne's blog notes that over 200 IDOR vulnerabilities are found and safely reported to customers every month. It's one of the most common vulnerability types.
- **Source:** https://www.hackerone.com/blog/how-idor-vulnerability-led-user-profile-modification

### 18. IDOR on PayPal - Adding Secondary Users
- **Severity:** High
- **Vulnerability Type:** IDOR
- **Platform:** HackerOne
- **Program:** PayPal
- **Bounty:** $10,500
- **Description:** An IDOR vulnerability in PayPal's account management allowed attackers to add secondary users to another person's PayPal account, gaining financial access to the victim's funds.
- **How It Was Found:** Testing the add secondary user functionality by manipulating account identifiers.
- **Impact:** Financial account compromise - attackers could add themselves to victim PayPal accounts.
- **Key Takeaway:** Financial platforms should be prioritized for IDOR testing due to the high business impact. Features that add users/permissions to accounts are critical test targets.
- **Source:** Referenced in Top 25 IDOR Reports

### 19. IDOR on Grubhub Checkout - Pay with Others' Credit Cards
- **Severity:** Critical
- **Vulnerability Type:** IDOR
- **Platform:** HackerOne
- **Program:** Grubhub
- **Bounty:** $5,000+
- **Description:** An IDOR vulnerability in Grubhub's /checkout/transaction_platform endpoint allowed attackers to use other users' registered credit cards when placing food orders. By modifying the payment method ID, an attacker could charge any user's card.
- **How It Was Found:** Intercepting checkout requests and modifying the payment method identifier to reference other users' saved payment methods.
- **Impact:** Direct financial harm - unauthorized charges to other users' credit cards.
- **Key Takeaway:** Payment and checkout endpoints with selectable payment methods are extremely high-value IDOR targets. Test by changing payment method IDs, shipping addresses, and billing details.
- **Source:** Referenced in Top 25 IDOR Reports

### 20. Top 235 IDOR Bug Bounty Reports Collection
- **Severity:** Various (Low to Critical)
- **Vulnerability Type:** IDOR
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** Various
- **Description:** A comprehensive collection of 235 IDOR bug bounty reports was compiled on Medium, covering a wide range of IDOR variants and affected platforms.
- **How It Was Found:** Aggregated from public disclosures across bug bounty platforms.
- **Impact:** Various - from information disclosure to full account takeover.
- **Key Takeaway:** Study large collections of IDOR reports to identify patterns and common vulnerable endpoints across different types of applications.
- **Source:** https://aimasterprompt.medium.com/top-235-idor-bug-bounty-reports-e00c8061fe28

---

## IDOR Hunting Methodology Summary

### Tools Commonly Used
- **Burp Suite** - Intercept and modify requests, use Autorize extension
- **Autorize (Burp Extension)** - Automated authorization testing
- **Match and Replace (Burp)** - Automatic ID swapping
- **Postman** - API testing with different authentication tokens
- **OWASP ZAP** - Authorization testing

### Common IDOR Locations
1. User profile view/edit endpoints
2. Order/transaction details
3. Support ticket systems
4. File/document access endpoints
5. API endpoints accepting object IDs
6. GraphQL queries and mutations
7. Password reset / email change features
8. Payment method management
9. Comment/post CRUD operations
10. Admin/management panels

### IDOR Testing Methodology
1. Create two accounts (Account A and Account B)
2. Perform actions with Account A and capture all requests
3. Identify all object references (user IDs, object IDs, UUIDs)
4. Replay requests from Account A using Account B's session
5. Try accessing Account A's objects using Account B's tokens
6. Test both horizontal IDOR (same privilege level) and vertical IDOR (different privilege levels)
7. Test with no authentication at all
8. Try predictable ID patterns (sequential, timestamps, etc.)

---

## Additional Reports (Expanded Collection)

### 21. IDOR on GraphQL Queries - BillingDocumentDownload and BillDetails (Shopify)
- **Severity**: High
- **Bounty**: $5,000
- **Program**: Shopify
- **Platform**: HackerOne
- **Description**: An IDOR vulnerability affected the BillingInvoice ID in both the BillingDocumentDownload and BillDetails GraphQL operations. Staff members could access billing information belonging to other shops by manipulating invoice IDs in GraphQL requests.
- **How Found**: Testing GraphQL operations with different BillingInvoice IDs while authenticated as a staff user from a different shop.
- **Impact**: Unauthorized access to other Shopify merchants' billing documents and financial details.
- **Key Takeaway**: GraphQL billing and financial operations are high-value IDOR targets. Always test ID parameters in GraphQL operations across tenant boundaries.
- **Source**: https://hackerone.com/reports/2207248

### 22. IDOR in activateFuelCard Allows Driver UUID Enumeration (Uber)
- **Severity**: Medium
- **Bounty**: $500
- **Program**: Uber
- **Platform**: HackerOne
- **Description**: An IDOR in Uber's activateFuelCard endpoint allowed an attacker to enumerate driver UUIDs by providing sequential card ID numbers. The endpoint returned a driver's UUID for any card ID without verifying authorization.
- **How Found**: Testing the fuel card activation endpoint with sequential card IDs and observing that driver UUIDs were leaked in responses.
- **Impact**: Mass enumeration of Uber driver UUIDs which could be used as a stepping stone for further attacks on driver accounts.
- **Key Takeaway**: Even seemingly low-impact IDOR (UUID enumeration) can be chained with other vulnerabilities for greater impact. Always report enumeration issues.
- **Source**: https://hackerone.com/reports/254151

### 23. IDOR on partners.uber.com - Override Administrator Documents (Uber)
- **Severity**: High
- **Bounty**: $500
- **Program**: Uber
- **Platform**: HackerOne
- **Description**: An IDOR in the /p3/drivers/uploadDocument endpoint on partners.uber.com allowed a driver to upload and overwrite documents belonging to other drivers or administrators on a multi-driver account.
- **How Found**: Intercepting the document upload request and changing the target driver/user ID parameter to reference another user on the platform.
- **Impact**: Ability to overwrite official documents of other drivers, potentially enabling identity fraud or disrupting driver accounts.
- **Key Takeaway**: File upload endpoints with user/object references are prime IDOR candidates. Test document management features by changing owner IDs in upload requests.
- **Source**: https://hackerone.com/reports/194594

### 24. IDOR Leaks Analytics of Any Uber Account (Uber)
- **Severity**: Medium
- **Bounty**: $500+
- **Program**: Uber
- **Platform**: HackerOne
- **Description**: An IDOR vulnerability allowed attackers to access analytics data belonging to any Uber user by manipulating account identifiers in API requests. The analytics endpoint did not validate that the requesting user owned the target account.
- **How Found**: Changing user UUID in analytics API requests to access data belonging to other users.
- **Impact**: Exposure of ride analytics, usage patterns, and potentially sensitive location data for any Uber user.
- **Key Takeaway**: Analytics and reporting endpoints often have weaker access controls than primary application features. Include them in your IDOR testing scope.
- **Source**: https://hackerone.com/reports/1116387

### 25. Sensitive User Information Disclosure via IDOR (Uber)
- **Severity**: High
- **Bounty**: $2,000+
- **Program**: Uber
- **Platform**: HackerOne
- **Description**: An attacker could insert another user's UUID into the userUuid POST parameter when requesting bonjour.uber.com/marketplace/_rpc?rpc=getConsentScreenDetails, retrieving personal data from the victim's account including their mobile auth token.
- **How Found**: Analyzing API calls and modifying the userUuid parameter to reference other users' UUIDs.
- **Impact**: Personal data exposure and mobile auth token leak, potentially enabling session hijacking.
- **Key Takeaway**: Auth tokens leaked via IDOR dramatically escalate impact. Always check what sensitive data is returned in IDOR responses beyond the obvious fields.
- **Source**: https://hackerone.com/reports/542340

### 26. IDOR in API Applications - Update Any API Application (Automattic/Pressable)
- **Severity**: High
- **Bounty**: $500+
- **Program**: Automattic
- **Platform**: HackerOne
- **Description**: An IDOR vulnerability in API applications allowed users to update API applications via endpoints at my.pressable.com/api/applications by changing the application ID, modifying applications belonging to other users.
- **How Found**: Testing API application management endpoints with application IDs belonging to other accounts.
- **Impact**: Unauthorized modification of other users' API applications, potentially redirecting API callbacks or changing application settings.
- **Key Takeaway**: API management panels within platforms are often overlooked. Test CRUD operations on API keys, applications, and OAuth clients for IDOR.
- **Source**: https://hackerone.com/reports/1695454

### 27. IDOR in External Status Check API (GitLab)
- **Severity**: Medium
- **Bounty**: $1,160
- **Program**: GitLab
- **Platform**: HackerOne
- **Description**: The API endpoint for returning approval from an external status check contained an IDOR that allowed any user to list information about all external status checks on the GitLab instance. The feature was an Ultimate-tier feature but could be accessed by starting a trial.
- **How Found**: Testing the external status check API endpoint by changing the status check ID and observing cross-project data leakage.
- **Impact**: Information disclosure of all external status checks across the entire GitLab instance, potentially revealing CI/CD pipeline details and security tooling.
- **Key Takeaway**: Premium/enterprise features accessible through trial accounts can be a way to test IDOR on endpoints with smaller user bases and potentially less hardening.
- **Source**: https://hackerone.com/reports/1372216

### 28. IDOR in Machine Learning Model Registry (GitLab)
- **Severity**: High
- **Bounty**: $1,160
- **Program**: GitLab
- **Platform**: HackerOne
- **Description**: A critical IDOR was discovered in GitLab's Machine Learning Model Registry that allowed attackers to access all private models and their versions. The models used guessable, incremental IDs, making enumeration trivial.
- **How Found**: Enumerating model IDs in the ML Model Registry API and discovering that authorization checks were missing for model access.
- **Impact**: Unauthorized access to proprietary machine learning models and their version history across all GitLab tiers.
- **Key Takeaway**: Newer features (like ML/AI integrations) are often added without the same access control rigor as core features. Target recently released functionality for IDOR.
- **Source**: https://medium.com/h7w/1-160-bounty-unveiling-gitlabs-idor-flaw-248cc766fd1b

### 29. IDOR on Acronis API Leaks Private User Information (Acronis)
- **Severity**: High
- **Bounty**: $500+
- **Program**: Acronis
- **Platform**: HackerOne
- **Description**: An IDOR vulnerability on the www.acronis.com API endpoint allowed attackers to steal private information including company name, user name, surname, and telephone number by manipulating user identifiers.
- **How Found**: Testing API endpoints with different user IDs and observing that sensitive PII was returned without proper authorization checks.
- **Impact**: Mass exposure of Acronis customer PII including names, company details, and phone numbers.
- **Key Takeaway**: B2B SaaS platforms often expose company and employee data through IDOR, which can be valuable for social engineering and further attacks.
- **Source**: https://hackerone.com/reports/1182465

### 30. IDOR Allows Access to Payment Data of Any User (Nord Security/NordVPN)
- **Severity**: Critical
- **Bounty**: Recognized (no monetary bounty)
- **Program**: Nord Security
- **Platform**: HackerOne
- **Description**: An IDOR vulnerability in a POST request to /api/v1/orders allowed unauthenticated access to payment data of any NordVPN user. The endpoint required no authentication to access order details.
- **How Found**: Testing payment-related API endpoints and discovering that the orders endpoint did not require authentication and accepted arbitrary user references.
- **Impact**: Exposure of payment information and order history of any NordVPN user.
- **Key Takeaway**: Always test payment and order endpoints both with and without authentication. Some IDOR vulnerabilities are compounded by missing authentication entirely.
- **Source**: https://hackerone.com/reports/751577

### 31. IDOR to View Order Information and PII (Affirm)
- **Severity**: High
- **Bounty**: $500
- **Program**: Affirm
- **Platform**: HackerOne
- **Description**: An IDOR vulnerability in Affirm's platform allowed viewing order information of other users along with their personal information by manipulating order identifiers in API requests.
- **How Found**: Intercepting order detail requests and changing the order ID to reference orders belonging to other users.
- **Impact**: Exposure of financial order details and personal information of Affirm users, a buy-now-pay-later service handling sensitive financial data.
- **Key Takeaway**: Fintech platforms handling lending and payment data are high-value targets. IDOR on order/transaction endpoints can expose both financial and personal data.
- **Source**: https://hackerone.com/reports/1323406

### 32. Broken Access Control (IDOR) in Hardcoded Zombie Endpoint (Bykea)
- **Severity**: High
- **Bounty**: Recognized (no monetary bounty)
- **Program**: Bykea
- **Platform**: HackerOne
- **Description**: An IDOR vulnerability in a hardcoded zombie endpoint within the Bykea ride-hailing app allowed malicious users to see other users' booking details, bids information, and bids configuration.
- **How Found**: Reverse engineering the mobile application to find hardcoded API endpoints, then testing them for authorization issues.
- **Impact**: Exposure of booking details, pricing bids, and internal configuration data for any Bykea user.
- **Key Takeaway**: Decompile mobile apps to find hardcoded API endpoints. "Zombie" endpoints (old, forgotten APIs) often lack proper access controls.
- **Source**: https://hackerone.com/reports/2374730

### 33. IDOR - Authenticated User Can Download Any Document (GSA/SmartPay)
- **Severity**: Medium
- **Bounty**: N/A (Government VDP)
- **Program**: GSA Bounty (U.S. Government)
- **Platform**: HackerOne
- **Description**: An IDOR at training.smartpay.gsa.gov allowed any authenticated user to download documents that disclose PII of other users and soldiers by changing document identifiers in download requests.
- **How Found**: Testing document download endpoints by modifying document IDs while authenticated as a low-privilege user.
- **Impact**: Exposure of PII belonging to government employees and military personnel through unauthorized document access.
- **Key Takeaway**: Government platforms often handle highly sensitive data. Even small IDOR issues on .gov domains can have outsized impact due to the sensitivity of the data.
- **Source**: https://hackerone.com/reports/245872

### 34. IDOR - Scheduled Data Leak via ProjectID (SingleStore)
- **Severity**: High
- **Bounty**: Recognized (no monetary bounty)
- **Program**: SingleStore
- **Platform**: HackerOne
- **Description**: An IDOR in the GetNotebookScheduledPaginatedJobs endpoint allowed authenticated users to access scheduled job information belonging to other users' projects by modifying the projectID parameter.
- **How Found**: Changing the projectID parameter in the scheduled jobs API endpoint to reference other users' projects.
- **Impact**: Exposure of scheduled job configurations and potentially sensitive query data belonging to other SingleStore users.
- **Key Takeaway**: Database-as-a-service platforms expose unique IDOR surfaces through project management and job scheduling features. Test multi-tenant boundaries in cloud database platforms.
- **Source**: https://hackerone.com/reports/3219944

### 35. IDOR Leads to View Phone Numbers of Riders/Drivers (Uber)
- **Severity**: Medium
- **Bounty**: $2,000
- **Program**: Uber
- **Platform**: HackerOne
- **Description**: Given a Rider or Driver's email address or UUID, an attacker could find out their actual phone number through an IDOR in Uber's API that did not properly restrict phone number lookups.
- **How Found**: Testing user lookup endpoints by providing email addresses or UUIDs and observing phone number data in responses.
- **Impact**: Privacy violation exposing phone numbers of millions of Uber riders and drivers.
- **Key Takeaway**: Phone number exposure is a significant privacy issue. Test all user lookup and search endpoints for information leakage beyond what should be publicly accessible.
- **Source**: https://hackerone.com/reports/225243

### 36. IDOR on Stocky Application - Low Stock, Variant, and Settings (Shopify)
- **Severity**: Medium
- **Bounty**: $750
- **Program**: Shopify
- **Platform**: HackerOne
- **Description**: An IDOR vulnerability on Shopify's Stocky inventory application allowed unauthorized access to Low Stock data, Variant information, Settings, and Column configurations belonging to other shops.
- **How Found**: Testing Stocky API endpoints by changing shop/resource IDs to access inventory data from other merchants.
- **Impact**: Exposure of competitor inventory levels, product variants, and business configuration from other Shopify stores.
- **Key Takeaway**: Third-party apps integrated into major platforms (like Shopify apps) often have their own IDOR vulnerabilities. Test each integrated application independently.
- **Source**: Referenced in Shopify HackerOne disclosures

### 37. IDOR to View Support Tickets on Seller Platform (Fintech)
- **Severity**: Critical
- **Bounty**: $5,000
- **Program**: Private Fintech Program
- **Platform**: HackerOne
- **Description**: A broken access control vulnerability allowed viewing support requests submitted by other users on a banking-related fintech platform by simply incrementing the ticket ID. The endpoint did not verify ticket ownership.
- **How Found**: Intercepting support ticket viewing requests, incrementing the ticket ID, and confirming access to other users' sensitive banking inquiries.
- **Impact**: Exposure of sensitive financial support requests containing banking details, transaction disputes, and personal information.
- **Key Takeaway**: Support/helpdesk ticket systems in financial applications are extremely high-value IDOR targets due to the rich customer data they contain.
- **Source**: https://www.webasha.com/blog/what-is-a-real-hackerone-broken-access-control-exploit-worth-5000-full-writeup-inside

### 38. Getting Access to Mod Logs from Any Public or Restricted Subreddit (Reddit)
- **Severity**: High
- **Bounty**: $5,000
- **Program**: Reddit
- **Platform**: HackerOne
- **Description**: Reddit failed to check if the user was a moderator of a particular subreddit when they attempted to access the mod logs via GraphQL. An attacker could change the subredditName parameter to access mod logs from any subreddit.
- **How Found**: Testing the GraphQL mod logs query by changing the subredditName parameter to reference subreddits where the attacker was not a moderator.
- **Impact**: Unauthorized access to moderator action logs for any subreddit, revealing moderator identities, removal reasons, and internal moderation patterns.
- **Key Takeaway**: Role-based access checks in GraphQL APIs often fail to validate context (like subreddit membership). Test GraphQL queries with context parameters belonging to unauthorized scopes.
- **Source**: https://portswigger.net/daily-swig/simple-idor-vulnerability-in-reddit-allowed-mischief-makers-to-perform-mod-actions

### 39. IDOR Leads to View PII on DoD System (U.S. Department of Defense)
- **Severity**: Critical
- **Bounty**: N/A (VDP)
- **Program**: U.S. Department of Defense
- **Platform**: HackerOne
- **Description**: An IDOR vulnerability on a Department of Defense application allowed viewing personally identifiable information of military personnel and government employees by changing user identifiers in API requests.
- **How Found**: Testing authenticated API endpoints by modifying user ID parameters to access records belonging to other users.
- **Impact**: Exposure of sensitive PII of military personnel, including names, addresses, and service details.
- **Key Takeaway**: Government VDP programs, while not offering monetary bounties, provide recognition and the chance to find critical vulnerabilities on systems protecting national security data.
- **Source**: https://hackerone.com/reports/2586641

### 40. IDOR on Profile Picture Mechanism Discloses Other Users' Photos
- **Severity**: Medium
- **Bounty**: $500+
- **Program**: Undisclosed
- **Platform**: HackerOne
- **Description**: An IDOR vulnerability in the profile picture upload/retrieval mechanism allowed accessing profile photos of other users by manipulating the user or image identifier in the request URL.
- **How Found**: Changing the user ID or image file reference in profile picture URLs to enumerate and access other users' photos.
- **Impact**: Privacy violation through unauthorized access to users' profile photos, potentially including photos not meant to be publicly visible.
- **Key Takeaway**: Media and file serving endpoints often have weaker access controls. Test image, document, and file download URLs for IDOR by changing identifiers.
- **Source**: Referenced in HackerOne IDOR disclosure collections

### 41. Privilege Escalation via /users/create_admin Endpoint (Shopify/Stocky)
- **Severity**: Critical
- **Bounty**: $1,600
- **Program**: Shopify
- **Platform**: HackerOne
- **Description**: A privilege escalation vulnerability on stocky.shopifyapps.com allowed a non-privileged user to create an administrative account by sending a direct request to the /users/create_admin endpoint, bypassing intended access restrictions.
- **How Found**: Discovering the /users/create_admin endpoint through forced browsing and testing it with a low-privilege session, finding that no authorization check was enforced.
- **Impact**: Any authenticated user could create admin accounts, gaining full administrative control over the Stocky inventory management application.
- **Key Takeaway**: Forced browsing to admin endpoints is a simple but effective technique. Always check if admin-only URL paths can be accessed directly by low-privilege users.
- **Source**: https://www.hackerone.com/blog/how-privilege-escalation-led-unrestricted-admin-account-creation-shopify

### 42. Privilege Escalation - Remove Business Owners (Yelp)
- **Severity**: Critical
- **Bounty**: $5,000+
- **Program**: Yelp
- **Platform**: HackerOne
- **Description**: A privilege escalation vulnerability in Yelp's business platform allowed a low-privileged user to bypass access controls and remove business owners from their own accounts through an improperly protected GraphQL API operation.
- **How Found**: Testing GraphQL mutations related to business user management with low-privilege credentials, discovering that owner removal was not restricted to authorized administrators.
- **Impact**: Any low-privilege business user could remove the actual business owner from their own Yelp business account, effectively taking over the business listing.
- **Key Takeaway**: Business management features with role hierarchies (owner > admin > user) are prime targets. Test if lower roles can perform actions reserved for higher roles, especially user removal and role changes.
- **Source**: https://www.appsecure.security/blog/yelp-bug-bounty-writeup-privilege-escalation

### 43. Privilege Escalation from Any User to Admin (GitLab)
- **Severity**: Critical
- **Bounty**: $10,000+
- **Program**: GitLab
- **Platform**: HackerOne
- **Description**: A privilege escalation vulnerability allowed any authenticated GitLab user to escalate their privileges to administrator level, gaining full control over the GitLab instance including access to all repositories, CI/CD pipelines, and user management.
- **How Found**: Testing role and permission boundaries by attempting admin-only operations with standard user credentials.
- **Impact**: Full administrative takeover of any GitLab instance, access to all source code, secrets, and CI/CD configurations.
- **Key Takeaway**: DevOps platforms like GitLab are extremely high-value targets. Privilege escalation to admin gives access to source code, deployment secrets, and infrastructure.
- **Source**: https://hackerone.com/reports/493324

### 44. IDOR via WakaTime - Create Accounts and Verify Emails (WakaTime)
- **Severity**: High
- **Bounty**: $500+
- **Program**: WakaTime
- **Platform**: HackerOne
- **Description**: An IDOR vulnerability allowed creating accounts and verifying email addresses on behalf of other users, bypassing the normal account creation and email verification flow.
- **How Found**: Manipulating user identifiers in the account creation and email verification API endpoints.
- **Impact**: Account impersonation and unauthorized email verification, potentially enabling social engineering attacks using verified accounts.
- **Key Takeaway**: Account creation and email verification flows should be tested for IDOR. Ability to create or verify accounts as other users is a serious authorization flaw.
- **Source**: https://hackerone.com/reports/244636

### 45. IDOR via Auth Header Replacement Leads to Account Takeover
- **Severity**: Critical
- **Bounty**: $3,000+
- **Program**: Undisclosed
- **Platform**: Private Program
- **Description**: A researcher discovered that an authentication header contained account IDs. By replacing the account ID in the header with a victim's ID, the attacker could change the victim's email address and then reset their password using the new email.
- **How Found**: Analyzing authentication headers in API requests and discovering that account-level authorization was derived from a manipulable header value rather than the session token.
- **Impact**: Full account takeover by chaining header manipulation with email change and password reset.
- **Key Takeaway**: Inspect all custom authentication headers for embedded user/account identifiers. If the server trusts a client-supplied ID in a header, it is effectively an IDOR.
- **Source**: https://medium.com/@bxrowski0x/how-to-find-idors-like-a-pro-158cf23baf23

### 46. IDOR in Banking Application via API Manipulation
- **Severity**: Critical
- **Bounty**: $3,500
- **Program**: Private Banking Program
- **Platform**: HackerOne
- **Description**: A researcher discovered an IDOR in a real-world banking application by manipulating API endpoints, allowing access to other customers' account details, transaction histories, and personal banking information.
- **How Found**: Systematic testing of banking API endpoints by replacing account and customer identifiers with those of other users.
- **Impact**: Access to other bank customers' account details, transaction histories, and sensitive financial data.
- **Key Takeaway**: Banking and fintech applications pay premium bounties for access control issues due to regulatory requirements. Financial data exposure has maximum business impact.
- **Source**: https://www.webasha.com/blog/what-is-an-example-of-a-real-bug-bounty-report-where-idor-was-used-to-exploit-a-banking-application

### 47. IDOR - POC Leads to Account Takeover via Profile Update
- **Severity**: Critical
- **Bounty**: $2,000+
- **Program**: Undisclosed
- **Platform**: Private Program
- **Description**: An attacker modified an ID parameter in a profile update request and successfully updated the victim's email address and other information, chaining IDOR with password reset for full account takeover.
- **How Found**: Testing profile update endpoints by changing the user ID in the request body while keeping the attacker's session token.
- **Impact**: Full account takeover through IDOR-based email change followed by password reset.
- **Key Takeaway**: Profile update IDOR that allows email changes is effectively a critical account takeover. Always test email change functionality for IDOR as a high-priority target.
- **Source**: https://cyb3rmind.medium.com/1-bug-bounty-poc-idor-leads-to-account-takeover-e500701a8004

### 48. IDOR on HackerOne Authorization Bypass in API
- **Severity**: High
- **Bounty**: $2,500
- **Program**: HackerOne
- **Platform**: HackerOne
- **Description**: An IDOR vulnerability in HackerOne's own API allowed authorization bypass, enabling access to resources belonging to other programs or users through manipulated API requests.
- **How Found**: Testing HackerOne's API endpoints with identifiers belonging to other programs and users.
- **Impact**: Unauthorized access to HackerOne program data, demonstrating that even security-focused platforms can have IDOR vulnerabilities.
- **Key Takeaway**: Security platforms are not immune to IDOR. Bug bounty platforms, security tools, and SIEM systems should all be tested for access control issues.
- **Source**: https://hackerone.com/reports/2139190

### 49. IDOR in Privilege Escalation (Automattic)
- **Severity**: High
- **Bounty**: $500+
- **Program**: Automattic
- **Platform**: HackerOne
- **Description**: A privilege escalation vulnerability in Automattic's platform allowed users to access functionality and data beyond their assigned permission level through object reference manipulation.
- **How Found**: Testing the boundaries of different user roles by attempting to access higher-privilege endpoints and resources.
- **Impact**: Unauthorized access to administrative functions and data on Automattic's platform.
- **Key Takeaway**: Test horizontal and vertical privilege escalation simultaneously. IDOR is not just about accessing another user's data at the same level - it can also grant elevated privileges.
- **Source**: https://hackerone.com/reports/13959

### 50. IDOR on Misconfigured OAuth Leads to Pre-Account Takeover
- **Severity**: Critical
- **Bounty**: $2,000+
- **Program**: Undisclosed
- **Platform**: HackerOne
- **Description**: A misconfigured OAuth implementation combined with IDOR allowed pre-account takeover where an attacker could register through social login before the victim, binding the victim's account to the attacker's OAuth identity without proper email verification.
- **How Found**: Analyzing the OAuth flow for email verification gaps and testing if social login could be used to claim accounts before the legitimate user registered.
- **Impact**: Pre-account takeover - the attacker could claim any unregistered account before the legitimate user, gaining full access upon the victim's first login.
- **Key Takeaway**: OAuth-based registration flows should verify email ownership before account binding. Test for pre-account takeover by registering via OAuth with an email address that has a pending invitation.
- **Source**: https://hackerone.com/reports/1074047

### 51. Shopify $50,000 IDOR - Access to Private Code Repositories
- **Severity**: Critical
- **Bounty**: $50,000
- **Program**: Shopify
- **Platform**: HackerOne
- **Description**: A computer science student discovered an IDOR vulnerability that blew a gaping hole in Shopify's software repositories, allowing unauthorized access to private code. This became one of the highest-paid IDOR bounties in Shopify's program.
- **How Found**: Testing repository access controls and finding that private repository identifiers could be accessed across organizational boundaries.
- **Impact**: Access to Shopify's private source code repositories, potentially exposing proprietary algorithms, API keys, and security-sensitive code.
- **Key Takeaway**: Source code repository access control issues command the highest bounties. IDOR in code hosting platforms can expose the crown jewels of any organization.
- **Source**: https://www.theregister.com/2021/07/27/shopify_bug_bounty_payout/

### 52. IDOR - Delete All Licenses and Certifications via GraphQL (HackerOne)
- **Severity**: Critical
- **Bounty**: $12,500
- **Program**: HackerOne
- **Platform**: HackerOne
- **Description**: The CreateOrUpdateHackerCertification GraphQL mutation could be used to delete all licenses and certifications from any user's HackerOne account. By modifying user identifiers in the GraphQL mutation, an attacker could wipe credential data from any hacker profile.
- **How Found**: Testing GraphQL mutations with modified user IDs, discovering that the CreateOrUpdateHackerCertification operation accepted arbitrary target user IDs.
- **Impact**: Destruction of any user's professional certifications and licenses, impacting their reputation and eligibility for bug bounty programs.
- **Key Takeaway**: GraphQL mutations that perform both create and update operations (CreateOrUpdate pattern) are especially dangerous because the update path may lack proper authorization checks.
- **Source**: https://hackerone.com/reports/2487889
