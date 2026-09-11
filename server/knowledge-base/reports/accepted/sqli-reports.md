# SQL Injection Bug Bounty Reports

> A collection of accepted/disclosed SQL Injection vulnerability reports from bug bounty programs.

---

### 1. SQL Injection via User-Agent Header (GSA/labs.data.gov)
- **Severity:** Critical
- **Vulnerability Type:** SQL Injection (Header-based)
- **Platform:** HackerOne
- **Program:** GSA Bounty
- **Bounty:** $2,000+
- **Description:** A SQL injection vulnerability was identified in labs.data.gov in the `/dashboard/datagov/csv_to_json` endpoint, exploitable via the User-Agent HTTP header. The application used the User-Agent value in a SQL query without sanitization.
- **How It Was Found:** Testing non-standard injection points (HTTP headers) with SQL injection payloads using sqlmap and manual testing.
- **Impact:** Full database access, potential data exfiltration from government databases.
- **Key Takeaway:** Don't limit SQL injection testing to form fields and URL parameters. HTTP headers (User-Agent, Referer, X-Forwarded-For, Cookie) are frequently overlooked injection points.
- **Source:** https://hackerone.com/reports/297478

### 2. Blind SQL Injection on U.S. Department of Defense Website
- **Severity:** Critical
- **Vulnerability Type:** Blind SQL Injection
- **Platform:** HackerOne
- **Program:** U.S. Department of Defense
- **Bounty:** N/A (VDP)
- **Description:** A blind SQL injection vulnerability was discovered in the User-Agent parameter of a U.S. Department of Defense website. The injection allowed boolean-based blind extraction of database contents.
- **How It Was Found:** Automated header injection testing with sqlmap, targeting the User-Agent header with time-based and boolean-based blind payloads.
- **Impact:** Access to sensitive DoD database contents, potential exposure of classified or sensitive information.
- **Key Takeaway:** Military/government systems often use legacy applications with SQL injection vulnerabilities. User-Agent injection is particularly effective because it bypasses most WAF rules that focus on URL parameters.
- **Source:** https://hackerone.com/reports/2597543

### 3. Blind SQL Injection on id.indrive.com
- **Severity:** Critical
- **Vulnerability Type:** Blind SQL Injection
- **Platform:** HackerOne
- **Program:** inDrive
- **Bounty:** $2,000+
- **Description:** A blind SQL injection vulnerability was found on inDrive's identity/authentication platform (id.indrive.com), allowing extraction of database data through boolean-based blind techniques.
- **How It Was Found:** Testing authentication endpoints with SQL injection payloads and observing differential responses.
- **Impact:** Access to user authentication data, potential compromise of user credentials for the ride-sharing platform.
- **Key Takeaway:** Authentication endpoints are high-value SQLi targets because they directly process user credentials. Even blind SQLi on auth endpoints can lead to mass credential extraction.
- **Source:** https://hackerone.com/reports/2051931

### 4. SQL Injection on www.drivegrab.com (Grab)
- **Severity:** Critical
- **Vulnerability Type:** SQL Injection
- **Platform:** HackerOne
- **Program:** Grab
- **Bounty:** $2,000+
- **Description:** A direct SQL injection vulnerability was found on Grab's website (www.drivegrab.com), allowing execution of arbitrary SQL queries against the backend database.
- **How It Was Found:** Testing input parameters with SQL injection payloads and identifying error-based injection points.
- **Impact:** Full database access for a major ride-sharing platform, potential exposure of user PII and driver information.
- **Key Takeaway:** Large tech companies may have vulnerable legacy subdomains or regional sites that don't receive the same security attention as the main product.
- **Source:** https://hackerone.com/reports/273946

### 5. SQL Injection through Formidable Pro WordPress Plugin (ImpressCMS)
- **Severity:** Critical
- **Vulnerability Type:** SQL Injection
- **Platform:** HackerOne
- **Program:** ImpressCMS
- **Bounty:** $500+
- **Description:** An SQL injection vulnerability was found in the Formidable Pro WordPress plugin through manipulated form submissions. The plugin failed to properly sanitize user input before including it in SQL queries.
- **How It Was Found:** Testing WordPress plugin form inputs with SQL injection payloads.
- **Impact:** Database compromise of WordPress sites using the vulnerable plugin.
- **Key Takeaway:** WordPress plugins are a rich target for SQL injection. Popular plugins with form-handling functionality should be tested for SQLi in form field values, especially in non-obvious parameters.
- **Source:** https://hackerone.com/reports/1081145

### 6. Union-Based SQL Injection on intensedebate.com (Automattic)
- **Severity:** Critical
- **Vulnerability Type:** Union-Based SQL Injection
- **Platform:** HackerOne
- **Program:** Automattic
- **Bounty:** $1,000+
- **Description:** A union-based SQL injection was found in the commenthistory endpoint on intensedebate.com. The UNION SELECT technique allowed direct extraction of database contents in the response.
- **How It Was Found:** Testing comment-related API endpoints with SQL injection payloads, specifically UNION-based techniques.
- **Impact:** Full database read access, extraction of user data and comment content.
- **Key Takeaway:** Comment systems and content management endpoints are common SQL injection targets. Union-based SQLi provides the most efficient data extraction when available.
- **Source:** https://hackerone.com/reports/1046084

### 7. SQL Injection on intensedebate.com (Second Finding - Automattic)
- **Severity:** Critical
- **Vulnerability Type:** SQL Injection
- **Platform:** HackerOne
- **Program:** Automattic
- **Bounty:** $1,000+
- **Description:** A second SQL injection vulnerability was found on Automattic's intensedebate.com service, separate from the union-based injection. This demonstrates that multiple injection points can exist in the same application.
- **How It Was Found:** Continued testing of different endpoints on the same application after the first SQLi finding.
- **Impact:** Database compromise of IntenseDebate service.
- **Key Takeaway:** When you find one SQL injection, keep looking - there are often more. The same development practices that led to the first vulnerability likely affect other endpoints.
- **Source:** https://hackerone.com/reports/1069561

### 8. SQL Injection on LocalTapiola Web Application
- **Severity:** Critical
- **Vulnerability Type:** SQL Injection
- **Platform:** HackerOne
- **Program:** LocalTapiola
- **Bounty:** $2,500+
- **Description:** SQL injection was found in the /webApp/oma_conf endpoint of LocalTapiola's web application. The vulnerability allowed execution of arbitrary SQL queries against the insurance company's database.
- **How It Was Found:** Systematic parameter testing with SQL injection payloads on the web application endpoints.
- **Impact:** Access to insurance company database, potential exposure of policyholder information and financial data.
- **Key Takeaway:** Insurance and financial institutions handle extremely sensitive data. SQL injection in these sectors has very high business impact and often results in significant bounties.
- **Source:** https://hackerone.com/reports/181803

### 9. Second SQL Injection on LocalTapiola
- **Severity:** Critical
- **Vulnerability Type:** SQL Injection
- **Platform:** HackerOne
- **Program:** LocalTapiola
- **Bounty:** $2,500+
- **Description:** A second SQL injection vulnerability was found in a different endpoint of LocalTapiola's application, demonstrating systemic SQL injection issues across the platform.
- **How It Was Found:** Testing additional endpoints after the first SQL injection discovery.
- **Impact:** Additional database access points, compounding the impact of the first finding.
- **Key Takeaway:** When an organization has one SQL injection, it often indicates a pattern of unsafe coding practices throughout the application. Explore all endpoints systematically.
- **Source:** https://hackerone.com/reports/200818

### 10. Blind SQL Injection on DoD (Second Finding)
- **Severity:** Critical
- **Vulnerability Type:** Blind SQL Injection
- **Platform:** HackerOne
- **Program:** U.S. Department of Defense
- **Bounty:** N/A (VDP)
- **Description:** Another blind SQL injection was found on a different U.S. DoD web property, reinforcing that government systems frequently have SQL injection vulnerabilities.
- **How It Was Found:** Automated scanning with sqlmap followed by manual verification.
- **Impact:** Access to DoD database contents.
- **Key Takeaway:** The U.S. DoD VDP has a massive attack surface with thousands of web applications. Systematic SQLi scanning of DoD assets can yield multiple findings.
- **Source:** https://hackerone.com/reports/313037

### 11. CVE-2024-42005: SQL Injection in Django (Internet Bug Bounty)
- **Severity:** High
- **Vulnerability Type:** SQL Injection
- **Platform:** HackerOne
- **Program:** Internet Bug Bounty
- **Bounty:** $2,500+
- **Description:** A potential SQL injection vulnerability was discovered in Django's QuerySet.values() and values_list() methods (CVE-2024-42005). This framework-level vulnerability affected all applications using the vulnerable Django versions.
- **How It Was Found:** Source code review of Django's ORM layer, analyzing how user input flows through QuerySet methods to SQL generation.
- **Impact:** All Django applications using the affected methods could be vulnerable to SQL injection.
- **Key Takeaway:** Framework-level SQL injection vulnerabilities have massive impact. Reviewing ORM and query builder source code in popular frameworks can lead to highly impactful findings.
- **Source:** https://hackerone.com/reports/2646493

### 12. Blind SQL Injection on Zomato (www.zomato.com)
- **Severity:** High
- **Vulnerability Type:** Blind SQL Injection
- **Platform:** HackerOne
- **Program:** Zomato (via Eternal)
- **Bounty:** $1,000
- **Description:** A blind SQL injection vulnerability was found on Zomato's main website, allowing boolean-based data extraction from the food delivery platform's database.
- **How It Was Found:** Parameter fuzzing and SQL injection testing on Zomato's web application endpoints.
- **Impact:** Access to Zomato's database containing user data, restaurant information, and order details.
- **Key Takeaway:** Food delivery and e-commerce platforms handle large volumes of user PII and payment data. SQLi on these platforms is always high-impact.
- **Source:** https://hackerone.com/reports/838855

### 13. Blind SQL Injection in Hall of Fap
- **Severity:** High
- **Vulnerability Type:** Blind SQL Injection
- **Platform:** HackerOne
- **Program:** Undisclosed
- **Bounty:** $500+
- **Description:** A blind SQL injection was discovered in a web application endpoint that processed user input without proper parameterization.
- **How It Was Found:** Automated SQL injection scanning with manual verification of blind injection conditions.
- **Impact:** Database data extraction through time-based or boolean-based blind techniques.
- **Key Takeaway:** Even applications with simple functionality can have SQL injection. Don't skip simpler endpoints in favor of only testing complex features.
- **Source:** https://hackerone.com/reports/295841

### 14. SQL Injection Leads to $$$ Bounty (Medium Writeup)
- **Severity:** Critical
- **Vulnerability Type:** SQL Injection
- **Platform:** Private Program
- **Program:** Undisclosed
- **Bounty:** Significant (undisclosed amount)
- **Description:** A researcher documented finding a critical SQL injection vulnerability that resulted in a significant bounty payout. The writeup details the methodology from initial reconnaissance to exploitation.
- **How It Was Found:** Starting with subdomain enumeration, followed by parameter fuzzing and SQL injection testing on discovered endpoints.
- **Impact:** Full database compromise.
- **Key Takeaway:** Comprehensive recon is essential before SQL injection testing. Map out all endpoints, parameters, and input fields before testing. Use tools like ParamSpider and Arjun for parameter discovery.
- **Source:** https://medium.com/@arrheniuspaelongan09/sql-injection-leads-to-bounty-how-i-found-a-critical-bug-cbacc35a2f19

### 15. Exploiting Boolean-Based SQL Injection (Bug Bounty Series)
- **Severity:** High
- **Vulnerability Type:** Boolean-Based Blind SQL Injection
- **Platform:** Private Program
- **Program:** Undisclosed
- **Bounty:** $1,000+
- **Description:** A detailed writeup of exploiting a boolean-based blind SQL injection vulnerability, including the methodology for extracting database names, table names, and column data character by character.
- **How It Was Found:** Identifying differential responses (true/false conditions) in application behavior when injecting SQL boolean expressions, then using sqlmap for automated extraction.
- **Impact:** Complete database extraction through boolean-based inference.
- **Key Takeaway:** Boolean-based blind SQLi is often missed by scanners. Learn to identify subtle differences in response content, status codes, or response times that indicate boolean conditions.
- **Source:** https://cyb3rmind.medium.com/4-bug-bounty-series-exploiting-boolean-based-sql-injection-3455d800892e

### 16. $500 SQL Injection on IKEA.es (First HackerOne Finding)
- **Severity:** High
- **Vulnerability Type:** SQL Injection
- **Platform:** HackerOne
- **Program:** IKEA
- **Bounty:** $500
- **Description:** A SQL injection vulnerability was found on IKEA's Spanish website (.ikea.es), representing the researcher's first finding on HackerOne.
- **How It Was Found:** Testing regional/localized versions of the IKEA website for SQL injection in product search and filtering features.
- **Impact:** Database access to IKEA's Spanish market data, potential customer data exposure.
- **Key Takeaway:** Regional/localized versions of websites often have different codebases and may be more vulnerable than the main site. Test all language/regional variants.
- **Source:** Referenced in Awesome-Bugbounty-Writeups repository

### 17. SQL Injection via Second-Order Injection
- **Severity:** High
- **Vulnerability Type:** Second-Order SQL Injection
- **Platform:** Various
- **Program:** Various
- **Bounty:** Varies
- **Description:** A technique where SQL injection payloads are stored in the database through one input point and later executed when used in a different SQL query in another part of the application. The initial input may be properly escaped, but when retrieved and used in a new query, it becomes dangerous.
- **How It Was Found:** Storing SQL injection payloads in profile fields, comments, or other stored data, then triggering execution through features that use that data in queries (reports, exports, admin views).
- **Impact:** Database compromise through indirect injection vectors that bypass input sanitization.
- **Key Takeaway:** Second-order SQL injection is extremely hard to detect with automated tools. Store payloads in every possible field and then trigger features that query that data (CSV export, PDF generation, admin panels).
- **Source:** Referenced in multiple bug bounty writeup collections

### 18. Blind SQL Injection on Mail.ru
- **Severity:** High
- **Vulnerability Type:** Blind SQL Injection
- **Platform:** HackerOne
- **Program:** Mail.ru
- **Bounty:** $5,000
- **Description:** A blind SQL injection was found on Mail.ru's platform, one of the highest-paid SQL injection reports with 330 upvotes, demonstrating the value placed on SQLi findings by major platforms.
- **How It Was Found:** Parameter testing with SQL injection payloads, using time-based blind techniques for confirmation.
- **Impact:** Access to Mail.ru's database containing email and user data for millions of users.
- **Key Takeaway:** Large email platforms hold massive amounts of sensitive data. SQLi on email platforms is among the highest-impact findings due to the volume and sensitivity of stored data.
- **Source:** Referenced in HackerOne Top SQLi Reports

### 19. SQL Injection via API Endpoint
- **Severity:** Critical
- **Vulnerability Type:** SQL Injection
- **Platform:** Various
- **Program:** Various
- **Bounty:** Varies
- **Description:** API endpoints are increasingly common SQL injection targets. REST and GraphQL APIs that construct SQL queries from request parameters without proper parameterization are vulnerable.
- **How It Was Found:** Testing API endpoints with SQL injection payloads in JSON body parameters, query strings, and path parameters.
- **Impact:** Database compromise through API attack vectors.
- **Key Takeaway:** Modern APIs (REST/GraphQL) are prime SQLi targets because they often bypass traditional WAF rules designed for form-based input. Test JSON parameter values with SQL injection payloads.
- **Source:** Multiple bug bounty writeup collections

### 20. SQL Injection Recon Methodology (InfoSec Writeups)
- **Severity:** Various
- **Vulnerability Type:** SQL Injection Methodology
- **Platform:** Various
- **Program:** Various
- **Bounty:** Various
- **Description:** A comprehensive guide to SQL injection reconnaissance for bug bounty hunters, covering automation, payloads, and deep reconnaissance techniques for finding SQLi in modern applications.
- **How It Was Found:** The writeup covers subdomain enumeration, parameter discovery, URL pattern analysis, and automated SQLi testing using custom workflows.
- **Impact:** Systematic methodology for finding SQL injection vulnerabilities.
- **Key Takeaway:** Combine subdomain enumeration (subfinder, amass), URL collection (waybackurls, gau), parameter extraction (ParamSpider), and targeted SQLi testing (sqlmap, ghauri) for maximum coverage.
- **Source:** https://infosecwriteups.com/mastering-sql-injection-recon-step-by-step-guide-for-bug-bounty-hunters-9f493fb058dd

---

## SQL Injection Hunting Methodology Summary

### Tools Commonly Used
- **sqlmap** - Automated SQL injection detection and exploitation
- **ghauri** - Advanced SQL injection detection tool
- **Burp Suite** - Proxy and scanner for manual/automated SQLi testing
- **ParamSpider** - URL parameter discovery
- **Arjun** - Hidden parameter discovery
- **Nuclei** - Template-based SQLi scanning
- **waybackurls / gau** - Historical URL collection for parameter mining

### Common SQL Injection Locations
1. Search fields and query parameters
2. Login forms (username/password fields)
3. URL path parameters (/users/1 -> /users/1')
4. HTTP headers (User-Agent, Referer, X-Forwarded-For)
5. Cookie values
6. JSON API body parameters
7. GraphQL query variables
8. File upload filenames
9. Sort/order/filter parameters
10. Hidden form fields and state parameters

### SQL Injection Types to Test
1. **Error-based** - Trigger SQL errors to extract data
2. **Union-based** - Use UNION SELECT to combine queries
3. **Boolean-based blind** - Infer data from true/false conditions
4. **Time-based blind** - Infer data from response time differences
5. **Out-of-band** - Exfiltrate data through DNS or HTTP requests
6. **Second-order** - Stored payloads triggered later in different queries
7. **Stacked queries** - Execute multiple statements with semicolons

---

## Additional Reports (Expanded Collection)

### 21. SQL Injection Extracts Starbucks Enterprise Accounting, Financial, Payroll Database
- **Severity**: Critical
- **Bounty**: $0 (recognition only)
- **Program**: Starbucks
- **Platform**: HackerOne
- **Description**: A SQL injection vulnerability allowed extraction of Starbucks' entire enterprise accounting, financial, and payroll database. This was the highest-upvoted SQLi report on HackerOne with 786 upvotes, demonstrating the massive impact possible through SQLi on enterprise systems.
- **How Found**: Testing enterprise web application endpoints for SQL injection in financial/accounting modules.
- **Impact**: Complete exposure of corporate financial records, payroll data, and accounting information for Starbucks globally.
- **Key Takeaway**: Enterprise internal applications (accounting, HR, payroll) are often less hardened than customer-facing apps and can yield the most sensitive data.
- **Source**: https://hackerone.com/reports/531051

### 22. Time-Based SQL Injection at city-mobil.ru (Mail.ru)
- **Severity**: Critical
- **Bounty**: $15,000
- **Program**: Mail.ru
- **Platform**: HackerOne
- **Description**: A time-based SQL injection was discovered on city-mobil.ru, a ride-hailing service owned by Mail.ru. This is the highest-paid SQLi report in the HackerOne dataset, earning $15,000 and receiving 631 upvotes.
- **How Found**: Testing ride-hailing platform endpoints with time-based blind SQL injection payloads and measuring response delays.
- **Impact**: Full database access to the ride-hailing service, including user data, driver information, and trip history.
- **Key Takeaway**: Ride-hailing and delivery platforms handle enormous volumes of user PII and location data. Time-based blind SQLi remains highly effective even when error messages are suppressed.
- **Source**: https://hackerone.com/reports/868436

### 23. SQL Injection at Razer Gold via txid Parameter
- **Severity**: Critical
- **Bounty**: $2,000
- **Program**: Razer
- **Platform**: HackerOne
- **Description**: SQL injection was found at sea-web.gold.razer.com/ajax-get-status.php via the txid (transaction ID) parameter. The vulnerability allowed direct manipulation of payment/transaction queries.
- **How Found**: Testing payment status endpoints with SQL injection payloads in transaction identifier parameters.
- **Impact**: Access to Razer Gold payment and transaction database, potential exposure of financial records and user payment information.
- **Key Takeaway**: Payment and transaction status endpoints are prime SQLi targets because they directly query financial databases. Transaction ID parameters are often overlooked injection points.
- **Source**: https://hackerone.com/reports/819738

### 24. SQL Injection in Razer Pay API (inviteFriend/getInviteHistoryLog)
- **Severity**: Critical
- **Bounty**: $2,000
- **Program**: Razer
- **Platform**: HackerOne
- **Description**: A SQL injection vulnerability was found in Razer Pay's API endpoint for invite friend history. The injection point was in the API path used to retrieve referral/invitation logs.
- **How Found**: Testing API endpoints related to social/referral features with SQL injection payloads in query parameters.
- **Impact**: Access to Razer Pay user data and referral history, potential exposure of payment information.
- **Key Takeaway**: Social features like invite/referral systems in payment platforms often have less security scrutiny than core payment flows but share the same database.
- **Source**: https://hackerone.com/reports/811111

### 25. SQL Injection Leading to RCE on QIWI (contact-sys.com)
- **Severity**: Critical
- **Bounty**: $0 (recognition)
- **Program**: QIWI
- **Platform**: HackerOne
- **Description**: A SQL injection on contactws.contact-sys.com in TScenObject action ScenObjects was escalated to full remote code execution. This report received 475 upvotes, demonstrating the extreme impact of SQLi-to-RCE chains.
- **How Found**: Discovering SQL injection in payment processing API endpoints, then escalating through database features (xp_cmdshell, INTO OUTFILE, etc.) to achieve code execution.
- **Impact**: Full server compromise of a payment processing system through SQL injection escalation.
- **Key Takeaway**: Always attempt to escalate SQLi to RCE. On MSSQL, try xp_cmdshell. On MySQL, try INTO OUTFILE to webroot. On PostgreSQL, try COPY TO/FROM PROGRAM.
- **Source**: https://hackerone.com/reports/816254

### 26. Blind SQL Injection on InnoGames
- **Severity**: Critical
- **Bounty**: $2,000
- **Program**: InnoGames
- **Platform**: HackerOne
- **Description**: A blind SQL injection vulnerability was found on an InnoGames property, receiving 432 upvotes on HackerOne. The gaming company's platform was vulnerable to boolean-based blind data extraction.
- **How Found**: Systematic SQL injection testing on gaming platform endpoints with blind injection techniques.
- **Impact**: Access to gaming platform database containing user accounts, game data, and potentially payment information.
- **Key Takeaway**: Gaming companies handle large user bases with payment data. Their web platforms are often developed with a focus on functionality over security.
- **Source**: https://hackerone.com/reports/758654

### 27. SQL Injection in Valve's report_xml.php ($25,000 Bounty)
- **Severity**: Critical
- **Bounty**: $25,000
- **Program**: Valve
- **Platform**: HackerOne
- **Description**: A SQL injection was found in Valve's report_xml.php through the countryFilter[] parameter. This is the highest-bounty SQLi report in the dataset at $25,000, with 397 upvotes. The array parameter was not properly sanitized before being included in SQL queries.
- **How Found**: Testing array parameters (param[]) in reporting endpoints. Array-type parameters often bypass basic input validation that only checks for string inputs.
- **Impact**: Full database access on Valve's reporting infrastructure, potential exposure of Steam user data and financial records.
- **Key Takeaway**: Array parameters (param[], param[0]) are frequently overlooked injection points. Test all parameter types including arrays, nested objects, and multi-value parameters.
- **Source**: https://hackerone.com/reports/383127

### 28. SQL Injection at fleet.city-mobil.ru (Mail.ru)
- **Severity**: Critical
- **Bounty**: $10,000
- **Program**: Mail.ru
- **Platform**: HackerOne
- **Description**: A second SQL injection was found on city-mobil.ru's fleet management platform, earning $10,000. The fleet management system for the ride-hailing service had a separate injection point from the earlier finding.
- **How Found**: After finding SQLi on the main platform, the researcher tested the fleet/driver management subdomain for similar vulnerabilities.
- **Impact**: Access to fleet management data including driver information, vehicle details, and operational data.
- **Key Takeaway**: When you find SQLi on one subdomain, test all related subdomains. Fleet/admin/management portals often share the same vulnerable codebase or development practices.
- **Source**: https://hackerone.com/reports/881901

### 29. Zomato Union SQLi + WAF Bypass
- **Severity**: Critical
- **Bounty**: $4,500
- **Program**: Zomato (Eternal)
- **Platform**: HackerOne
- **Description**: A Union-based SQL injection was found on www.zomato.com with a WAF bypass. The researcher identified a way to circumvent Zomato's Web Application Firewall to exploit the injection point, earning $4,500 with 320 upvotes.
- **How Found**: Identifying SQL injection behind a WAF, then developing bypass techniques using encoding, case manipulation, or alternative SQL syntax to evade WAF rules.
- **Impact**: Full database read access on Zomato's platform, bypassing security controls designed to prevent such attacks.
- **Key Takeaway**: WAFs are not a complete defense against SQLi. Learn WAF bypass techniques: double URL encoding, Unicode normalization, comment injection (/*!SELECT*/), case alternation, and HTTP parameter pollution.
- **Source**: https://hackerone.com/reports/403616

### 30. SQL Injection on Cookie Parameter (MTN Group)
- **Severity**: Critical
- **Bounty**: $0 (VDP)
- **Program**: MTN Group
- **Platform**: HackerOne
- **Description**: SQL injection was found in a cookie parameter on an MTN Group web application, receiving 320 upvotes. Cookie-based injection bypasses most input validation that focuses on GET/POST parameters.
- **How Found**: Testing cookie values for SQL injection by modifying cookie parameters in HTTP requests and observing differential responses.
- **Impact**: Database access through an injection vector that bypasses standard parameter-level security controls.
- **Key Takeaway**: Cookies are a critical but overlooked injection surface. Many WAFs and input validation routines focus only on query strings and POST bodies, leaving cookies unprotected.
- **Source**: https://hackerone.com/reports/761304

### 31. Blind SQLi Leading to RCE on Starbucks (Unauthenticated API)
- **Severity**: Critical
- **Bounty**: $0 (recognition)
- **Program**: Starbucks
- **Platform**: HackerOne
- **Description**: A blind SQL injection found on an unauthenticated test API webservice on Starbucks infrastructure was escalated to full remote code execution. The chain went from blind SQLi to data extraction to RCE, all from an unauthenticated starting point.
- **How Found**: Discovering exposed test/staging API endpoints through reconnaissance, then testing them for SQL injection, and finally escalating to RCE through database features.
- **Impact**: Full server compromise starting from an unauthenticated test API endpoint.
- **Key Takeaway**: Test and staging environments often have weaker security controls. Combine subdomain enumeration with API discovery to find forgotten test endpoints that may have SQLi vulnerabilities.
- **Source**: https://hackerone.com/reports/592400

### 32. SQL Injection at Razer Easy2Pay with Signature Validation Bypass
- **Severity**: Critical
- **Bounty**: $4,000
- **Program**: Razer
- **Platform**: HackerOne
- **Description**: SQL injection was found at api.easy2pay.co via the TransID parameter, with a bypass of signature validation. The researcher circumvented the API's cryptographic signature check to reach the vulnerable SQL query.
- **How Found**: Analyzing the API signature validation logic, finding a bypass, then exploiting SQL injection in the transaction ID parameter behind the signature check.
- **Impact**: Access to the payment processing database, potential manipulation of payment transactions.
- **Key Takeaway**: Signature/HMAC validation on API parameters can sometimes be bypassed. Study the signature algorithm and look for weaknesses like parameter order manipulation, empty signature acceptance, or replay attacks.
- **Source**: https://hackerone.com/reports/894325

### 33. SQL Injection in Hyperpure (Zomato B2B)
- **Severity**: Critical
- **Bounty**: $2,000
- **Program**: Zomato (Eternal)
- **Platform**: HackerOne
- **Description**: SQL injection was found on www.hyperpure.com, Zomato's B2B supply chain platform. This demonstrated that even subsidiary/specialized platforms of large companies can have critical SQL injection vulnerabilities.
- **How Found**: Testing B2B/supply chain platforms associated with the main target, finding SQL injection in business-facing endpoints.
- **Impact**: Access to Zomato's B2B supply chain database, including restaurant supplier information and business data.
- **Key Takeaway**: B2B platforms and subsidiary websites of large companies often receive less security testing. Expand your scope to include supply chain and business-facing properties.
- **Source**: https://hackerone.com/reports/1044716

### 34. Boolean-Based SQL Injection on relap.io (Mail.ru)
- **Severity**: High
- **Bounty**: $0 (recognition)
- **Program**: Mail.ru
- **Platform**: HackerOne
- **Description**: A boolean-based SQL injection was found on relap.io, a content recommendation platform owned by Mail.ru. The vulnerability allowed data extraction through boolean inference techniques.
- **How Found**: Testing subsidiary services and acquisitions of large companies. Relap.io was identified as a Mail.ru property through OSINT and ASN research.
- **Impact**: Database access on a content recommendation service, potential exposure of publisher and user data.
- **Key Takeaway**: Map out the full corporate structure and acquisitions of target companies. Subsidiaries and acquired companies often have legacy code with SQL injection vulnerabilities.
- **Source**: https://hackerone.com/reports/745938

### 35. Blind SQL Injection + Profile Comment Deletion on Pornhub
- **Severity**: High
- **Bounty**: $0 (recognition)
- **Program**: Pornhub
- **Platform**: HackerOne
- **Description**: A blind SQL injection was found in the "like" function that could also be used to make profile comments from any user disappear. This was a 2-in-1 finding: SQLi plus a business logic bug that allowed content manipulation.
- **How Found**: Testing social interaction features (likes, comments, follows) for SQL injection, particularly in the ID parameters used for these operations.
- **Impact**: Database data extraction plus the ability to delete/hide user comments, demonstrating both data breach and content manipulation impacts.
- **Key Takeaway**: Social features (likes, follows, reactions) often pass numeric IDs directly into SQL queries. Test these interaction endpoints thoroughly for injection.
- **Source**: https://hackerone.com/reports/363815

### 36. Blind SQL Injection on Starbucks.com.gt with WAF Bypass
- **Severity**: Critical
- **Bounty**: $0 (recognition)
- **Program**: Starbucks
- **Platform**: HackerOne
- **Description**: Blind SQL injection was found on the Guatemalan Starbucks website (starbucks.com.gt) with a WAF bypass technique. Regional Starbucks sites were vulnerable even when the main site was hardened.
- **How Found**: Testing country-specific/regional websites of the target company, then developing WAF bypass techniques for the blind injection.
- **Impact**: Database access on regional Starbucks infrastructure, potential exposure of local customer data.
- **Key Takeaway**: Regional TLDs and country-specific sites (.gt, .sg, .cn) are often maintained by different teams with varying security standards. Always enumerate and test regional variants.
- **Source**: https://hackerone.com/reports/549355

### 37. SQL Injection in GraphQL Endpoint (HackerOne)
- **Severity**: Critical
- **Bounty**: $0 (internal)
- **Program**: HackerOne
- **Platform**: HackerOne
- **Description**: SQL injection was found in HackerOne's own GraphQL endpoint through the embedded_submission_form_uuid parameter. This vulnerability on the bug bounty platform itself received 170 upvotes.
- **How Found**: Testing GraphQL query variables and parameters for SQL injection, focusing on UUID-type parameters that are often passed directly to database queries.
- **Impact**: Potential access to HackerOne's database containing vulnerability reports, user data, and bounty information.
- **Key Takeaway**: GraphQL endpoints are increasingly common SQLi targets. Test all GraphQL variables, especially those used for filtering, sorting, and lookup operations (UUIDs, IDs, slugs).
- **Source**: https://hackerone.com/reports/435066

### 38. SQL Injection on docs.atavist.com (Automattic)
- **Severity**: Critical
- **Bounty**: $0 (recognition)
- **Program**: Automattic
- **Platform**: HackerOne
- **Description**: SQL injection found on docs.atavist.com, a publishing platform owned by Automattic (parent of WordPress.com). The documentation/publishing platform had injectable parameters.
- **How Found**: Enumerating Automattic's full portfolio of web properties and testing each for SQL injection.
- **Impact**: Database access on the Atavist publishing platform, potential exposure of publisher content and user accounts.
- **Key Takeaway**: Large companies like Automattic own many web properties beyond their main product. Enumerate all acquisitions and subsidiary domains for testing.
- **Source**: https://hackerone.com/reports/1039315

### 39. SQL Injection with Direct Output at news.mail.ru
- **Severity**: Critical
- **Bounty**: $7,500
- **Program**: Mail.ru
- **Platform**: HackerOne
- **Description**: An unauthenticated SQL injection with direct output was found on news.mail.ru. Unlike blind injection, this vulnerability returned query results directly in the response, making exploitation trivial.
- **How Found**: Testing the news portal's endpoints for error-based and union-based SQL injection, finding that results were reflected directly in the page output.
- **Impact**: Immediate, direct access to database contents without the need for blind extraction techniques.
- **Key Takeaway**: Direct output (error-based or union-based) SQLi is the most impactful variant. When found, it allows immediate data extraction without the time-consuming character-by-character extraction of blind techniques.
- **Source**: https://hackerone.com/reports/818972

### 40. SQL Injection at Palantir (CVE-2021-38159)
- **Severity**: Critical
- **Bounty**: $0 (recognition)
- **Program**: Palantir Public
- **Platform**: HackerOne
- **Description**: SQL injection at files.palantir.com due to CVE-2021-38159, a known vulnerability in third-party software. The Palantir instance was running a vulnerable version that allowed SQL injection through crafted requests.
- **How Found**: Scanning Palantir infrastructure for known CVEs, identifying an unpatched instance vulnerable to CVE-2021-38159.
- **Impact**: Database access on Palantir's file management infrastructure, a particularly sensitive target given Palantir's role in data analytics.
- **Key Takeaway**: Known CVEs in third-party software are a goldmine for bug bounty. Maintain a database of SQLi CVEs and scan target infrastructure for unpatched instances using Nuclei templates.
- **Source**: https://hackerone.com/reports/1525200

### 41. SQL Injection in Structure Plugin (ExpressionEngine)
- **Severity**: High
- **Bounty**: $0 (recognition)
- **Program**: ExpressionEngine
- **Platform**: HackerOne
- **Description**: SQL injection found in the Structure plugin for ExpressionEngine CMS, receiving 119 upvotes. The plugin failed to sanitize user input before constructing SQL queries.
- **How Found**: Code review of CMS plugins, identifying user input that flows into SQL queries without parameterization.
- **Impact**: Database compromise of any ExpressionEngine site using the Structure plugin.
- **Key Takeaway**: CMS plugins and extensions are a rich source of SQL injection. Review third-party plugins for popular CMS platforms (WordPress, ExpressionEngine, Drupal) for SQL injection.
- **Source**: https://hackerone.com/reports/3249794

### 42. SQL Injection + Insecure Deserialization Leading to RCE on Krisp.ai
- **Severity**: Critical
- **Bounty**: $0 (recognition)
- **Program**: Krisp
- **Platform**: HackerOne
- **Description**: A SQL injection vulnerability was chained with insecure deserialization to achieve full remote code execution on krisp.ai. This demonstrates the power of vulnerability chaining where two medium-impact bugs combine into critical RCE.
- **How Found**: Finding SQL injection first, then discovering that the application also had insecure deserialization. Chaining both to escalate from data access to code execution.
- **Impact**: Full remote code execution on Krisp's infrastructure through a multi-stage exploit chain.
- **Key Takeaway**: Always look for ways to chain vulnerabilities. SQLi combined with deserialization, file write, or other bugs can escalate to RCE. Document all findings even if individually they seem lower impact.
- **Source**: https://hackerone.com/reports/1842674

### 43. SQL Injection in URL Path (MTN Group)
- **Severity**: Critical
- **Bounty**: $0 (VDP)
- **Program**: MTN Group
- **Platform**: HackerOne
- **Description**: SQL injection found in URL paths on MTN Group infrastructure. Rather than in query parameters, the injection point was in the URL path itself (e.g., /resource/INJECTION_HERE/action).
- **How Found**: Testing URL path segments for SQL injection, not just query parameters. Path-based injection is often missed by automated scanners.
- **Impact**: Database access through URL path manipulation.
- **Key Takeaway**: URL path segments are an underestimated injection surface. REST-style URLs like /users/123/orders may have injectable path segments. Test by replacing IDs with SQL payloads.
- **Source**: https://hackerone.com/reports/2958619

### 44. SQL Injection on Acronis Agent Manager
- **Severity**: Critical
- **Bounty**: $0 (recognition)
- **Program**: Acronis
- **Platform**: HackerOne
- **Description**: SQL injection was found in Acronis' agent-manager component, receiving 235 upvotes. The management interface for backup agents had injectable parameters.
- **How Found**: Testing enterprise management consoles for SQL injection in agent management and configuration endpoints.
- **Impact**: Database access on Acronis backup infrastructure, potential compromise of backup data and agent configurations.
- **Key Takeaway**: Enterprise backup and management software often has SQL injection in administrative interfaces. These are high-value targets because they manage access to backed-up data.
- **Source**: https://hackerone.com/reports/962889

### 45. SQL Injection on Uber Partner EU
- **Severity**: High
- **Bounty**: $1,500
- **Program**: Uber
- **Platform**: HackerOne
- **Description**: SQL injection on uberpartner.eu led to exposure of sensitive user data of Uber partners/drivers. The European partner portal had different security controls than the main Uber platform.
- **How Found**: Testing regional partner/driver portals that are separate from the main consumer-facing application.
- **Impact**: Exposure of Uber partner/driver sensitive data including personal information and financial records.
- **Key Takeaway**: Partner/vendor portals are often separate codebases with less security investment. Ride-sharing driver portals, merchant dashboards, and supplier portals are all excellent SQLi targets.
- **Source**: https://hackerone.com/reports/361623

### 46. SQL Injection on Uber sctrack.email.uber.com.cn
- **Severity**: High
- **Bounty**: $4,000
- **Program**: Uber
- **Platform**: HackerOne
- **Description**: SQL injection found on Uber's Chinese email tracking subdomain (sctrack.email.uber.com.cn). The email tracking service had injectable parameters in its tracking pixel/link system.
- **How Found**: Enumerating Uber's full subdomain space including regional domains, then testing email-related subdomains for injection.
- **Impact**: Database access on Uber's email tracking infrastructure, potential exposure of email campaign data and user tracking information.
- **Key Takeaway**: Email tracking subdomains and marketing infrastructure are often separate systems with their own databases. Look for tracking parameters (utm_*, click IDs, open tracking pixels) as injection points.
- **Source**: https://hackerone.com/reports/150156

### 47. SQL Injection in GitLab MilestoneFinder
- **Severity**: High
- **Bounty**: $2,000
- **Program**: GitLab
- **Platform**: HackerOne
- **Description**: SQL injection was found in GitLab's MilestoneFinder order method. The sorting/ordering functionality accepted user input that was incorporated into SQL ORDER BY clauses without proper sanitization.
- **How Found**: Testing sort and order parameters in GitLab's milestone listing functionality with SQL injection payloads.
- **Impact**: Database access on GitLab instances, potential exposure of source code repositories and user data.
- **Key Takeaway**: ORDER BY injection is commonly overlooked. Sort parameters, column names in ORDER BY, and direction (ASC/DESC) fields are often vulnerable because they cannot use parameterized queries in the same way as WHERE clauses.
- **Source**: https://hackerone.com/reports/298176

### 48. SQL Injection on Mozilla OIDC Proxy via invite_code
- **Severity**: Critical
- **Bounty**: $0 (VDP)
- **Program**: Mozilla
- **Platform**: HackerOne
- **Description**: SQL injection was found on Mozilla's OIDC proxy service (prod.oidc-proxy.prod.webservices.mozgcp.net) via the invite_code parameter used for Mozilla social platform registration.
- **How Found**: Testing authentication and registration flows, particularly invite/referral code parameters that interact with database lookups.
- **Impact**: Database access on Mozilla's identity infrastructure, potential compromise of authentication systems.
- **Key Takeaway**: Invite codes, referral codes, and token-based lookup parameters are common injection points because they directly query the database and are often implemented as simple string comparisons.
- **Source**: https://hackerone.com/reports/2209130

### 49. SQL Injection in Django FilteredRelation
- **Severity**: High
- **Bounty**: $0 (framework)
- **Program**: Django
- **Platform**: HackerOne
- **Description**: SQL injection vulnerability when using FilteredRelation in Django's ORM. This framework-level bug affected all Django applications using the FilteredRelation feature, demonstrating that even well-audited ORMs can have injection points.
- **How Found**: Source code review of Django's ORM, specifically analyzing how FilteredRelation constructs SQL queries and identifying an injection vector in the annotation process.
- **Impact**: All Django applications using FilteredRelation on PostgreSQL were potentially vulnerable to SQL injection.
- **Key Takeaway**: ORM-level SQL injection affects all applications using the framework. Finding SQLi in Django, Rails ActiveRecord, or Hibernate has massive impact across thousands of applications.
- **Source**: https://hackerone.com/reports/3292573

### 50. SQL Injection in Django Q Objects (_connector)
- **Severity**: High
- **Bounty**: $0 (framework)
- **Program**: Django
- **Platform**: HackerOne
- **Description**: SQL injection through unvalidated _connector parameter in Django Q Objects. The Q object's connector logic did not validate user input, allowing injection through crafted query filters.
- **How Found**: Analyzing Django's query construction logic, identifying that the _connector parameter in Q objects was not properly validated before being used in SQL generation.
- **Impact**: Any Django application that passed user input to Q object connectors was vulnerable to SQL injection.
- **Key Takeaway**: Framework internals like query builders, ORM methods, and filter constructors are high-value audit targets. Even mature frameworks like Django continue to have SQLi findings in their ORM layers.
- **Source**: https://hackerone.com/reports/3335709

### 51. Woocommerce SQL Injection in WC_Report_Coupon_Usage
- **Severity**: High
- **Bounty**: $0 (recognition)
- **Program**: Automattic
- **Platform**: HackerOne
- **Description**: SQL injection found in WooCommerce's reporting functionality, specifically in the WC_Report_Coupon_Usage class. The coupon usage reporting feature constructed SQL queries using unsanitized input.
- **How Found**: Code review of WooCommerce's reporting modules, identifying SQL query construction that incorporated user-controlled parameters without proper escaping.
- **Impact**: Database access on any WooCommerce store using the coupon reporting feature, affecting millions of e-commerce sites worldwide.
- **Key Takeaway**: WooCommerce powers a massive percentage of e-commerce sites. Vulnerabilities in reporting and analytics features of widely-used plugins have enormous scale impact.
- **Source**: https://hackerone.com/reports/3198980

### 52. SQL Injection in Nextcloud (Arbitrary SQL Command Injection)
- **Severity**: High
- **Bounty**: $0 (recognition)
- **Program**: Nextcloud
- **Platform**: HackerOne
- **Description**: Arbitrary SQL command injection was discovered in Nextcloud, the open-source file hosting platform. The vulnerability allowed execution of arbitrary SQL commands against the Nextcloud database.
- **How Found**: Testing Nextcloud's API endpoints and data access layers for SQL injection, identifying a path where user input reaches SQL execution without parameterization.
- **Impact**: Full database compromise of Nextcloud instances, potential access to all stored files, user credentials, and shared data.
- **Key Takeaway**: Self-hosted open-source platforms like Nextcloud are excellent targets for code review. The source code is available for thorough analysis of SQL query construction patterns.
- **Source**: https://hackerone.com/reports/508487

### 53. SQL Injection on OLX Indonesia
- **Severity**: Critical
- **Bounty**: $0 (recognition)
- **Program**: OLX
- **Platform**: HackerOne
- **Description**: SQL injection was found on www.olx.co.id, the Indonesian OLX classifieds platform. The regional marketplace had injectable parameters in its listing/search functionality.
- **How Found**: Testing regional e-commerce/classifieds platforms for SQL injection in search, filtering, and listing endpoints.
- **Impact**: Database access on OLX Indonesia, exposure of buyer/seller data, listings, and contact information.
- **Key Takeaway**: Classifieds and marketplace platforms in developing markets often have weaker security. Regional versions of global platforms are prime targets.
- **Source**: https://hackerone.com/reports/639876

### 54. SQL Injection Delivery-club.ru via ClickHouse (Mail.ru)
- **Severity**: Critical
- **Bounty**: $5,000
- **Program**: Mail.ru
- **Platform**: HackerOne
- **Description**: SQL injection was found in delivery-club.ru's analytics using ClickHouse, a columnar database. This is notable because ClickHouse injection differs from traditional MySQL/PostgreSQL injection in syntax and capabilities.
- **How Found**: Testing analytics and reporting endpoints that use non-standard databases (ClickHouse, Cassandra, MongoDB) with database-specific injection payloads.
- **Impact**: Access to delivery platform analytics data, including order volumes, user behavior, and business metrics.
- **Key Takeaway**: Modern applications use non-traditional databases (ClickHouse, Elasticsearch, MongoDB). Learn injection techniques specific to these databases. ClickHouse SQL syntax differs from MySQL and requires different payloads.
- **Source**: https://hackerone.com/reports/1024773

### 55. SQL Injection in Uber WordPress Plugin (Huge IT Video Gallery)
- **Severity**: High
- **Bounty**: $3,000
- **Program**: Uber
- **Platform**: HackerOne
- **Description**: SQL injection was found in a WordPress plugin (Huge IT Video Gallery) used on drive.uber.com/frmarketplace. The third-party WordPress plugin had SQL injection in its gallery functionality.
- **How Found**: Identifying that the target used WordPress with specific plugins, then testing known vulnerabilities in those plugins on the target's installation.
- **Impact**: Database access on Uber's French marketplace platform through a vulnerable WordPress plugin.
- **Key Takeaway**: Even large companies use WordPress with third-party plugins. Identify the CMS and plugin stack using tools like WPScan, then test for known plugin vulnerabilities and zero-days.
- **Source**: https://hackerone.com/reports/125932

### 56. Blind SQL Injection on Starbucks News
- **Severity**: High
- **Bounty**: $0 (recognition)
- **Program**: Starbucks
- **Platform**: HackerOne
- **Description**: Time-based blind SQL injection on news.starbucks.com. The news/blog subdomain had injectable parameters allowing time-based data extraction.
- **How Found**: Testing content management subdomains (news, blog, press) for SQL injection, using time-based blind techniques for confirmation.
- **Impact**: Database access on Starbucks' news platform, potential pivot to other connected internal systems.
- **Key Takeaway**: Content subdomains (news, blog, press) often run separate CMS platforms that may have SQL injection vulnerabilities. They are frequently deprioritized in security reviews.
- **Source**: https://hackerone.com/reports/198292

### 57. SQL Injection in CVE Discovery Search (HackerOne)
- **Severity**: High
- **Bounty**: $0 (internal)
- **Program**: HackerOne
- **Platform**: HackerOne
- **Description**: A second SQL injection was found on HackerOne itself, this time in the CVE discovery search functionality. The search feature for looking up CVE identifiers had an injectable parameter.
- **How Found**: Testing search functionality on HackerOne's platform, specifically the CVE lookup/discovery features with SQL injection payloads.
- **Impact**: Potential access to HackerOne's CVE database and associated vulnerability information.
- **Key Takeaway**: Search functionality is one of the most common SQL injection vectors. Any search feature that queries a database should be tested for injection, especially when it supports advanced search operators.
- **Source**: https://hackerone.com/reports/1893800

### 58. SQL Injection on Sony via Unnamed Parameter
- **Severity**: Critical
- **Bounty**: $0 (recognition)
- **Program**: Sony
- **Platform**: HackerOne
- **Description**: SQL injection found on a Sony web property through an undisclosed parameter, receiving 72 upvotes. Sony's entertainment infrastructure had injectable endpoints.
- **How Found**: Systematic parameter testing on Sony's web infrastructure, identifying injectable parameters through error-based detection.
- **Impact**: Database access on Sony's infrastructure, potential exposure of entertainment platform data.
- **Key Takeaway**: Large entertainment companies like Sony have extensive web infrastructure. Their gaming, music, and movie platforms each represent separate attack surfaces with different security postures.
- **Source**: https://hackerone.com/reports/1935151

### 59. SQL Injection on Yahoo HK Promotion
- **Severity**: High
- **Bounty**: $0 (recognition)
- **Program**: Yahoo!
- **Platform**: HackerOne
- **Description**: SQL injection found on Yahoo's Hong Kong promotional page. One of the earliest disclosed SQLi reports on HackerOne, demonstrating that even tech giants have had SQL injection vulnerabilities.
- **How Found**: Testing Yahoo's regional promotional/marketing pages for SQL injection in campaign parameters.
- **Impact**: Database access on Yahoo's promotional infrastructure for the Hong Kong market.
- **Key Takeaway**: Marketing and promotional pages are often built quickly with less security review. Campaign-specific pages, landing pages, and promotional microsites are excellent SQLi targets.
- **Source**: https://hackerone.com/reports/3039

### 60. Type Juggling to PHP Object Injection to SQL Injection Chain (ExpressionEngine)
- **Severity**: Critical
- **Bounty**: $0 (recognition)
- **Program**: ExpressionEngine
- **Platform**: HackerOne
- **Description**: A multi-stage exploit chain starting with PHP type juggling, leading to PHP object injection, and finally achieving SQL injection. This demonstrates sophisticated vulnerability chaining in PHP applications.
- **How Found**: Deep analysis of PHP type comparison behavior, identifying type juggling vulnerabilities that could be leveraged for object injection, which in turn allowed SQL injection.
- **Impact**: Full database compromise through a complex exploit chain that individually relied on seemingly minor vulnerabilities.
- **Key Takeaway**: PHP applications are particularly susceptible to type juggling attacks. Understand PHP's loose comparison (==) vs strict comparison (===) and how type juggling can chain into object injection and SQL injection.
- **Source**: https://hackerone.com/reports/202774

### 61. Ability to Escape Database Transaction Leading to Code Execution (HackerOne)
- **Severity**: Critical
- **Bounty**: $0 (internal)
- **Program**: HackerOne
- **Platform**: HackerOne
- **Description**: SQL injection that allowed escaping database transactions to achieve arbitrary code execution on HackerOne's own platform. This demonstrates how SQL injection can be escalated beyond data access to full code execution by manipulating database transaction boundaries.
- **How Found**: Advanced SQL injection testing that explored transaction control statements (COMMIT, ROLLBACK) to escape the current transaction context and execute arbitrary commands.
- **Impact**: Code execution on HackerOne's infrastructure through SQL injection escalation.
- **Key Takeaway**: SQL injection escalation to code execution is possible through transaction escape, stacked queries, or database-specific features. Always try to escalate SQLi beyond just data extraction.
- **Source**: https://hackerone.com/reports/1663299

### 62. Blind SQL Injection on Informatica
- **Severity**: High
- **Bounty**: $0 (recognition)
- **Program**: Informatica
- **Platform**: HackerOne
- **Description**: Blind SQL injection found at tsftp.informatica.com, an enterprise data management platform. The SFTP-related web interface had injectable parameters that allowed time-based blind data extraction.
- **How Found**: Testing enterprise software administration interfaces for SQL injection, particularly file transfer and data management endpoints.
- **Impact**: Database access on Informatica's infrastructure, potential exposure of enterprise data management configurations and customer data.
- **Key Takeaway**: Enterprise data management platforms are high-value targets because they connect to and manage multiple databases. A single SQLi in these platforms can provide access to metadata about connected systems.
- **Source**: https://hackerone.com/reports/1034625

### 63. SQL Injection on IBM Access Control Panel
- **Severity**: High
- **Bounty**: $0 (recognition)
- **Program**: IBM
- **Platform**: HackerOne
- **Description**: SQL injection found in IBM's access control panel combined with broken access control in the admin panel. The access management system had injectable parameters in its user lookup functionality.
- **How Found**: Testing enterprise access control and identity management interfaces for SQL injection in user search, authentication, and authorization endpoints.
- **Impact**: Access to IBM's access control database, potential exposure of access policies, user credentials, and role assignments.
- **Key Takeaway**: Access control and IAM (Identity and Access Management) panels are prime targets. SQLi in authentication systems directly exposes credentials and access policies.
- **Source**: https://hackerone.com/reports/1355817

### 64. NoSQL Injection Leaks Visitor Token and Livechat Messages (Rocket.Chat)
- **Severity**: High
- **Bounty**: $0 (recognition)
- **Program**: Rocket.Chat
- **Platform**: HackerOne
- **Description**: NoSQL injection in Rocket.Chat leaked visitor tokens and livechat messages. The MongoDB-backed chat platform was vulnerable to NoSQL injection through query operator manipulation ($gt, $ne, $regex).
- **How Found**: Testing MongoDB-backed applications with NoSQL injection payloads using query operators like {"$gt": ""}, {"$ne": null}, and {"$regex": ".*"} in JSON parameters.
- **Impact**: Exposure of chat messages and authentication tokens, enabling impersonation of chat visitors.
- **Key Takeaway**: NoSQL injection is the SQL injection equivalent for MongoDB/NoSQL databases. Test JSON API parameters with MongoDB operators ($gt, $ne, $regex, $where). Tools like nosqlmap can automate detection.
- **Source**: https://hackerone.com/reports/2580062

### 65. SQL Injection in IBM URL Path Processing
- **Severity**: High
- **Bounty**: $0 (recognition)
- **Program**: IBM
- **Platform**: HackerOne
- **Description**: SQL injection found in URL path processing on www.ibm.com. The injection was in the URL path itself rather than in query parameters, a less common but increasingly important injection vector.
- **How Found**: Manipulating URL path segments with SQL injection payloads, testing REST-style URL structures where path components are used in database queries.
- **Impact**: Database access on IBM's main website infrastructure.
- **Key Takeaway**: URL path injection is underestimated. Modern REST APIs use path segments as database query parameters. Test paths like /api/resource/{id} by replacing {id} with injection payloads.
- **Source**: https://hackerone.com/reports/1527284
