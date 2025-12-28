import { useState, useEffect } from 'react';
import { Modal, Button, Form, ListGroup, Badge, Spinner, Alert, Accordion, Card } from 'react-bootstrap';

const QUESTIONS = [
  {
    category: 'Application Identity & Scope',
    questions: [
      'What is the primary function of the application?',
      'Is it consumer-facing, enterprise-facing, internal, or partner-facing?',
      'Is the application a single product or part of a larger platform?',
      'Are there multiple subdomains serving different functions?',
      'Are there multiple environments publicly accessible (prod, staging, beta)?',
      'Is the application region-specific or global?',
      'Are there mobile apps, desktop apps, or browser extensions associated with it?',
      'Is the web app a full product or a thin UI over APIs?',
      'Does the application expose public documentation or help portals?',
      'Is the app intended to be embedded or integrated into other sites?'
    ]
  },
  {
    category: 'Technology Stack & Frameworks',
    questions: [
      'What frontend framework is used?',
      'Is the app a Single Page Application?',
      'Is server-side rendering used?',
      'What backend language(s) are implied?',
      'Is the backend REST, GraphQL, or mixed?',
      'Are API versioning patterns present?',
      'Are build tools identifiable from assets?',
      'Are framework or library versions exposed?',
      'Are deprecated or end-of-life libraries in use?',
      'Are custom client-side frameworks present?'
    ]
  },
  {
    category: 'Hosting, Infrastructure & Delivery',
    questions: [
      'Is the application behind a CDN?',
      'Which CDN or edge provider is used?',
      'What server software is observable?',
      'Is a load balancer or reverse proxy in use?',
      'Is the app hosted in a public cloud?',
      'Can the cloud provider be identified?',
      'Are multiple services hosted on the same domain?',
      'Is virtual hosting used?',
      'Are containerization or serverless hints present?',
      'Are internal hostnames or regions leaked in responses?'
    ]
  },
  {
    category: 'Network & Transport Security',
    questions: [
      'Is HTTPS enforced everywhere?',
      'Is HSTS enabled?',
      'Which TLS versions are supported?',
      'Are weak cipher suites accepted?',
      'Is HTTP/2 or HTTP/3 used?',
      'Are cookies marked Secure?',
      'Are cookies marked HttpOnly?',
      'Is SameSite set on cookies?',
      'Are authentication cookies scoped to subdomains?',
      'Are multiple domains involved in session handling?'
    ]
  },
  {
    category: 'Traffic Controls & Abuse Protection',
    questions: [
      'Is a Web Application Firewall present?',
      'Can the WAF vendor be identified?',
      'Is bot detection or fingerprinting in use?',
      'Is rate limiting observable?',
      'Is CAPTCHA used anywhere in the app?',
      'Is CAPTCHA conditional or global?',
      'Are request challenges used (JS challenges, proof-of-work)?',
      'Are IP-based restrictions present?',
      'Does behavior differ for authenticated users?',
      'Are automated clients treated differently?'
    ]
  },
  {
    category: 'Authentication & Identity Model',
    questions: [
      'Is authentication required to access core functionality?',
      'What authentication methods are supported?',
      'Are third-party IdPs used?',
      'Is OAuth or OIDC used?',
      'Are multiple login methods available?',
      'Is MFA supported?',
      'Is MFA optional or mandatory?',
      'Are long-lived sessions used?',
      'Are refresh tokens observable client-side?',
      'Are authentication flows shared across domains?'
    ]
  },
  {
    category: 'Authorization, Roles & Data Model',
    questions: [
      'Are multiple user roles visible?',
      'Are role distinctions observable in the UI?',
      'Is the application multi-tenant?',
      'Are organizations, teams, or workspaces present?',
      'Are user identifiers exposed client-side?',
      'Are object identifiers exposed globally?',
      'Are shared resources visible?',
      'Are admin interfaces exposed?',
      'Are feature flags visible client-side?',
      'Are permissions enforced centrally or per-service?'
    ]
  },
  {
    category: 'Client-Side, Integrations & Policies',
    questions: [
      'What third-party scripts are loaded?',
      'Are analytics platforms present?',
      'Are customer support widgets present?',
      'Are payment providers integrated?',
      'Are external APIs called from the browser?',
      'Are API keys present client-side?',
      'Is a Content Security Policy present?',
      'Is the CSP strict or permissive?',
      'Is CORS implemented?',
      'Is source code or documentation publicly available?'
    ]
  },
  {
    category: 'Cloud Infrastructure & Services',
    questions: [
      'Are cloud storage buckets accessible (S3, Azure Blob, GCS)?',
      'Are bucket/container names discoverable or predictable?',
      'Are cloud metadata endpoints accessible?',
      'Are serverless functions identifiable?',
      'Are cloud service URLs exposed in client-side code?',
      'Is the cloud region/zone disclosed?',
      'Are CDN or object storage URLs structured predictably?',
      'Are cloud resource naming patterns consistent?',
      'Are AWS ARNs, Azure Resource IDs, or GCP project IDs leaked?',
      'Are infrastructure-as-code templates publicly accessible?'
    ]
  },
  {
    category: 'API Architecture & GraphQL',
    questions: [
      'Does the application use GraphQL?',
      'Is GraphQL introspection enabled?',
      'Are API endpoints versioned?',
      'Are deprecated API versions still accessible?',
      'Is the API documentation publicly available?',
      'Are websockets or SSE used for real-time features?',
      'Are REST API endpoints discoverable through OPTIONS requests?',
      'Is there an API gateway or BFF (Backend for Frontend)?',
      'Are internal/debugging endpoints exposed?',
      'Are API responses verbose with metadata?'
    ]
  },
  {
    category: 'Public Information & OSINT',
    questions: [
      'Are employee emails or usernames predictable?',
      'Is company GitHub/GitLab organization public?',
      'Are public repositories related to this application?',
      'Are commits containing secrets, keys, or credentials visible?',
      'Are subdomains enumerable through certificate transparency?',
      'Are job postings revealing tech stack details?',
      'Are error messages leaking internal paths or usernames?',
      'Are backup files, config files, or archives publicly accessible?',
      'Is sensitive information in JavaScript source maps?',
      'Are API docs, changelogs, or internal wikis indexed by search engines?'
    ]
  }
];

const QUESTION_GUIDANCE = {
  'What is the primary function of the application?': {
    why: `Understanding the primary function is the foundation of effective security testing because it shapes everything about how the application operates and where vulnerabilities are most likely to exist.

Different application types have fundamentally different attack surfaces. An e-commerce platform handles payments and inventory, making it susceptible to price manipulation, cart vulnerabilities, and payment bypass issues. A social media app manages user relationships and content sharing, creating risks around privacy controls, content injection, and account takeover. A SaaS application processes business data with complex authorization models, opening doors to privilege escalation and data exposure.

Business logic vulnerabilities are the highest-impact bugs you'll find, and they're entirely dependent on understanding what the application is supposed to do. You can't identify when something is broken if you don't know how it should work. When you understand the core function, you can ask critical questions: "What would happen if I could manipulate this price?" or "What if I could access another user's workspace?" These questions lead directly to critical findings.

Security assumptions often align with business function. A banking app assumes financial transactions follow strict workflows. A healthcare portal assumes patient data stays isolated. When you know the primary function, you know which security assumptions to challenge and where developers might have taken shortcuts or made dangerous assumptions about trust.`,
    how: `Start with the homepage and marketing materials as your first information source. Read the value proposition, feature descriptions, and any "How it Works" sections. Companies invest heavily in explaining their product clearly to customers, which means this information is accurate and comprehensive. Take notes on the core use cases they advertise.

Next, explore the main navigation and user interface without logging in. What actions can you take? What's the primary call-to-action? An e-commerce site pushes you to browse and buy. A SaaS tool encourages signup and onboarding. A content platform wants you to read or watch. The UI reveals priorities and core functions through design.

Create a test account and complete the primary user journey. If it's a shopping app, try to make a purchase (you can abandon at payment). If it's a project management tool, create a project and invite a team member. If it's a social network, post content and connect with others. Walk through the happy path to understand the intended workflow.

Review the about page, terms of service, and privacy policy. These legal documents reveal the business model, data handling practices, and often mention features or integrations not obvious from the UI. Look for phrases like "our platform enables..." or "we process...". Privacy policies especially reveal what data flows through the system.

Check for public documentation, help centers, or knowledge bases. These resources explain features in detail, often with screenshots and step-by-step guides. They're goldmine for understanding edge cases, admin features, and complex workflows that aren't obvious from casual use.

As a bug bounty hunter, use this information to build a mental model of the application's trust boundaries, data flows, and critical operations. Document the core function in your notes because you'll reference it constantly when you find odd behavior and need to determine if it's a vulnerability or intended functionality.`
  },
  'Is it consumer-facing, enterprise-facing, internal, or partner-facing?': {
    why: `The target audience fundamentally shapes the security model, attack surface, and vulnerability priorities. Each audience type has distinct trust assumptions, authentication patterns, and common weaknesses that directly inform your testing strategy.

Consumer-facing applications prioritize ease of use over complex security controls. They typically have simple registration (email + password), minimal verification, and broad public access. This creates a larger unauthenticated attack surface and makes user enumeration, credential stuffing, and account takeover more feasible. Bug bounty hunters often find more low-hanging fruit in consumer apps because rapid user onboarding takes precedence over security hardening.

Enterprise applications implement complex authentication (SSO, SAML, Active Directory integration) and authorization models (roles, groups, departments). While these add security layers, they also create complexity where bugs hide. Multi-tenancy, privilege escalation, and authorization bypass vulnerabilities are common in enterprise apps. The permission model is sophisticated enough that developers make mistakes in edge cases.

Partner-facing applications bridge trust boundaries between organizations, creating unique attack opportunities. They often integrate with partner APIs, share data across organizational boundaries, and implement partnership-specific business logic. These trust relationships and integrations are prime targets for privilege escalation, data exposure, and business logic exploitation.

Internal applications, when exposed, are goldmines because they often lack the security hardening of public-facing apps. Developers assume "internal" means "trusted" and skip input validation, authentication checks, or authorization controls. Finding exposed internal apps (through subdomain enumeration or misconfiguration) can lead to critical findings.`,
    how: `Examine the registration and signup process first. Consumer apps let anyone sign up with just an email address. Enterprise apps require corporate email domains, invitation codes, or administrator provisioning. Partner apps may require pre-registration, contract numbers, or verification steps. The signup friction immediately reveals the target audience.

Check authentication methods available at login. Consumer apps typically offer email/password and sometimes social login (Google, Facebook). Enterprise apps prominently display "Sign in with SSO" or "Use your company credentials". Partner apps might have custom login portals or API key authentication. These authentication patterns are strong audience indicators.

Review the pricing page and feature descriptions. Look for "enterprise plans" with features like "SSO", "SAML integration", "user provisioning", "audit logs", "dedicated support", or "SLA guarantees". These explicitly signal enterprise audience. Consumer apps advertise individual user features. Partner portals mention "partner dashboard" or "integration management".

Explore the application's help documentation and knowledge base. Consumer docs focus on end-user tasks. Enterprise docs discuss deployment, integration, security compliance, and administrative functions. Partner docs explain API integration, webhook configuration, and partner-specific workflows.

Look for organizational structure indicators in the UI. Enterprise apps have concepts like "organizations", "workspaces", "teams", or "departments". Consumer apps focus on individual accounts. Partner apps have "partner accounts", "reseller portals", or "integration settings". The data model reveals the audience.

Check for admin or configuration interfaces. Enterprise applications expose administrative controls for managing users, setting policies, and configuring integrations. Consumer apps have minimal admin features. The presence of sophisticated admin panels indicates enterprise focus.

Document your findings because audience type determines which vulnerability classes to prioritize. Consumer apps: focus on account takeover, rate limiting, and input validation. Enterprise apps: test authorization, multi-tenancy, and privilege escalation. Partner apps: examine API security, integration points, and cross-organizational data access. Your testing strategy should match the audience's security model.`
  },
  'Is the application a single product or part of a larger platform?': {
    why: `Understanding whether you're testing a standalone application or part of a larger ecosystem is critical because platform architectures introduce shared services, cross-application trust relationships, and attack vectors that don't exist in isolated applications.

Platform applications often share authentication and authorization systems across multiple services. A single sign-on (SSO) system might grant access to dozens of sub-applications. If you can compromise or manipulate the central authentication service, you've potentially gained access to the entire platform. This makes authentication vulnerabilities more valuable because the impact multiplies across all connected services.

Shared data stores and services create opportunities for privilege escalation and unauthorized access. When multiple applications read from the same database or API, a vulnerability in one service can expose data from others. You might exploit a low-security application (like a marketing site) to access data intended only for a high-security application (like an admin panel).

Platform architectures rely heavily on internal APIs and service-to-service communication. These internal APIs often have weaker security than public APIs because developers assume they're protected by network segmentation or assumed trust. If you can access internal API endpoints through SSRF, misconfiguration, or exposed services, you bypass intended security boundaries.

Cross-application session handling in platforms can be exploited. Cookies scoped to the parent domain (.platform.com) allow session tokens to be valid across all sub-applications. An XSS in any one application can steal credentials valid for the entire platform. Understanding the platform architecture helps you recognize when a seemingly minor vulnerability has platform-wide impact.`,
    how: `Look for consistent branding, navigation, or UI elements that appear across different sections of the application. Platform products often have a unified header with links to other services, a common account menu, or shared navigation. If you see links to distinctly different applications that share your session, you're looking at a platform.

Check the domain structure carefully. Platform applications often use subdomains for different services: app.platform.com, admin.platform.com, api.platform.com, docs.platform.com. If you see multiple subdomains serving different functions but sharing authentication, you're dealing with a platform architecture.

Examine your authentication cookies and their scope. If cookies are set with Domain=.platform.com (note the leading dot), they're accessible to all subdomains. This is a strong indicator of a platform where multiple services share authentication. Single products typically scope cookies to the specific domain.

Explore the main domain and any parent domains. If you're testing app.specificservice.com, try visiting specificservice.com or www.specificservice.com. Often the parent domain hosts a platform homepage with links to multiple products or services. This reveals the broader ecosystem you're testing within.

Review the account settings and profile pages. Platform accounts typically have sections like "Connected Services", "Authorized Applications", or "Manage Access" that show all the different services connected to your account. This explicitly maps the platform's scope.

Analyze network traffic for API calls to shared services. Look for requests to common domains like auth.platform.com, api.platform.com, or identity.platform.com that suggest centralized services. Shared authentication, user management, or data services indicate platform architecture.

Search for public documentation, blog posts, or architecture diagrams. Companies often publish technical overviews of their platform, explaining how services interconnect. This documentation is reconnaissance gold, revealing internal architecture and potential attack surfaces.

Map all discovered services and their relationships in your notes. Document shared authentication, common APIs, and data flows between services. Understanding the platform architecture lets you chain vulnerabilities across services, escalate privileges between applications, and recognize when a vulnerability in one component affects the entire ecosystem. Platform-wide impact significantly increases the severity of your findings.`
  },
  'Are there multiple subdomains serving different functions?': {
    why: `Subdomains dramatically expand your attack surface, and critically, they often have inconsistent security postures. While the main application at example.com might have strong security controls, blog.example.com or staging.example.com might be running outdated software, have weaker authentication, or expose debug endpoints.

Cookie scope is a major vulnerability area with subdomains. When cookies are scoped to the parent domain (Domain=.example.com), any subdomain can read those cookies. This means a successful XSS on a low-security subdomain like marketing.example.com can steal authentication cookies for the main application, leading to complete account takeover. This is why many major bug bounties pay highly for XSS on ANY subdomain.

Subdomain takeover is a critical vulnerability class that exists specifically because of multi-subdomain architectures. When a subdomain points to an external service (like AWS S3, GitHub Pages, or Heroku) that's been decommissioned, you can claim that service and serve content on the organization's subdomain. This leads to cookie theft, phishing, and full compromise of user trust.

Different subdomains often require different authentication levels or have different authorization models. You might find that admin.example.com has weak authentication compared to the main app, or that api.example.com accepts requests without the same CSRF protections as the web interface. Each subdomain is essentially a separate application that needs independent security evaluation.`,
    how: `Start with automated DNS enumeration using multiple tools because each finds different subdomains. Run subfinder, amass, and assetfinder against the target domain. Use multiple tools because they query different data sources - Certificate Transparency logs, DNS databases, search engines, and web archives. Combine the results for comprehensive coverage.

Examine SSL certificates carefully for Subject Alternative Names (SANs). Visit the main domain and click the padlock icon to view the certificate. SANs list all domains covered by that certificate, often revealing subdomains the company wants to secure. Use sites like crt.sh to search Certificate Transparency logs for historical and current certificates.

Manually explore the main application looking for links, redirects, and references to other subdomains. Check the source code, JavaScript files, and API responses for URLs. Pay special attention to authentication flows, email templates, and error messages, as these often reference other subdomains.

Review HTTP security headers, particularly Content-Security-Policy, which lists allowed sources for scripts, images, and other resources. These headers often reveal subdomains used for APIs, CDN content, or analytics. The CSP policy is essentially a map of the application's domain architecture.

Use DNS brute-forcing for common subdomain patterns after your initial enumeration. Tools like dnsgen can generate permutations based on discovered subdomains (if you find dev.example.com, try dev-api.example.com). Focus on patterns like: staging, dev, test, admin, api, vpn, mail, internal, etc.

As you test, document each subdomain's purpose, technology stack, and authentication requirements in your recon notes. Create a priority list based on functionality - admin panels, API endpoints, and authentication services should be tested first. Cross-reference subdomains with your scope document to ensure you're authorized to test each one.`
  },
  'Are there multiple environments publicly accessible (prod, staging, beta)?': {
    why: `Non-production environments are a bug bounty hunter's secret weapon because they consistently have weaker security postures than production while containing similar (or identical) code and data. Finding exposed staging or development environments often leads to critical discoveries.

Staging and development environments frequently have debug features enabled that production has disabled. Debug endpoints, verbose error messages, exposed stack traces, and development tools can leak internal paths, database queries, API keys, and source code. These information disclosures directly aid further exploitation and are often findings themselves.

Test data and default credentials plague non-production environments. Developers create test accounts with simple passwords (admin/admin, test/test123) for convenience during development. These credentials often work because no one bothers to secure environments they assume are internal. This instant access bypasses all authentication security.

Non-production environments run outdated code. Production might be on version 2.5 with security patches, while staging runs version 2.1 with known CVEs. Organizations prioritize production updates and let staging lag behind. Testing against older versions lets you exploit patched vulnerabilities without triggering production security monitors.

Security monitoring and WAF rules are typically relaxed or disabled in non-production. Your aggressive testing, payload fuzzing, and vulnerability scanning won't trigger alerts or blocks. You can test more freely, iterate faster, and validate findings without fear of being banned or reported. This makes non-production environments ideal for thorough technical testing.`,
    how: `Start with systematic subdomain enumeration targeting common environment naming patterns. Use tools like subfinder, amass, or assetfinder to search for: staging.target.com, dev.target.com, test.target.com, uat.target.com, beta.target.com, sandbox.target.com, qa.target.com, preprod.target.com. Also try prefixes: target-staging.com, target-dev.com.

Examine SSL certificates for Subject Alternative Names (SANs) that might list non-production environments. Organizations often include all environments in their wildcard certificates or multi-domain certificates. Visit crt.sh and search for %.target.com to see all certificate mentions.

Look for environment indicators in HTTP responses. Check headers like X-Environment, X-Stage, or custom headers mentioning dev/staging. Error pages sometimes reveal the environment: "Error in staging database" or "Dev mode enabled". The Server header might indicate test vs. production configurations.

Try common environment paths on the production domain: target.com/staging, target.com/dev, target.com/beta. Some organizations deploy multiple environments to subdirectories rather than subdomains. Check robots.txt and sitemap.xml for references to non-production paths.

Search GitHub, GitLab, and other code repositories for the target organization. Configuration files, CI/CD scripts, and documentation often contain URLs for staging and development environments. Search for patterns like "staging_url", "dev_endpoint", or environment variable configurations.

Use Google dorking to find exposed environments: site:target.com inurl:staging, site:target.com inurl:dev, site:target.com inurl:beta. Search engines index non-production environments when they're not properly restricted. You can also search for error messages or debug output that leaked environment information.

When you find a non-production environment, test authentication immediately. Try default credentials (admin/admin, admin/password, test/test, demo/demo), look for exposed admin panels, and check if authentication is required at all. Many staging environments skip authentication for developer convenience.

Document all discovered environments with their URLs, apparent purpose, and any security differences from production. Test each environment thoroughly - a critical vulnerability in staging that also exists in production is a valid finding, plus you've validated it in a safer environment. Always confirm if findings in non-production also affect production before reporting, and clearly distinguish where the vulnerability exists in your report.`
  },
  'Is the application region-specific or global?': {
    why: `Understanding the application's geographic scope reveals infrastructure design, data flow patterns, compliance requirements, and potential region-specific vulnerabilities that directly impact your testing approach and finding severity.

Global applications must handle data sovereignty and regional compliance requirements (GDPR in EU, CCPA in California, PIPEDA in Canada). These requirements create region-specific implementations, data handling differences, and potential compliance gaps. A vulnerability that exposes EU user data has different severity than one affecting only US users due to GDPR penalties.

Regional implementations often have inconsistent security controls. The main US application might be hardened and well-tested, while the recently-launched EU version has weaker input validation or missing security headers. Organizations roll out features and security updates gradually across regions, creating windows where some regions are vulnerable while others are patched.

Geolocation-based access controls can be bypassed through VPNs or proxy servers. Some applications restrict features or content based on IP geolocation, assuming users can't circumvent these checks. Testing from different geographic locations or using VPNs reveals if region restrictions are enforced server-side (secure) or client-side (bypassable).

Regional domains and CDN configurations may expose different attack surfaces. target.com, target.co.uk, and target.de might run on different infrastructure, have different security configurations, or even be different applications despite similar branding. Each regional deployment is essentially a separate target that needs independent security testing.`,
    how: `Look for language or region selectors in the UI. Many global applications have dropdowns, flags, or links for changing regions/languages. Click these and observe what changes: Does the domain change (target.com to target.de)? Does the URL path change (/en-us/ to /de-de/)? Do cookies or headers change? Document all region switching mechanisms.

Check for regional top-level domains (ccTLDs). Search for the application with different country codes: .co.uk (UK), .de (Germany), .fr (France), .ca (Canada), .au (Australia), .jp (Japan), etc. Visit these domains and see if they're separate applications or redirects to the main domain with region parameters.

Examine HTTP response headers for geographic indicators. Look for headers like CF-IPCountry (Cloudflare), X-GeoIP-Country, X-Forwarded-For-Continent, or custom headers revealing CDN edge locations. These headers show what geographic information the application tracks and how it might behave differently per region.

Test with VPNs or proxy services from different countries. Connect through a VPN exit node in different regions and access the application. Does it automatically redirect you? Does pricing change? Do available features differ? Are there different authentication requirements? Geographic testing reveals region-specific behavior and restrictions.

Review the privacy policy and terms of service for regional mentions. Legal documents often explicitly list which regions are served, where data is stored ("EU customer data is stored in EU data centers"), and which laws apply per region. This reveals the geographic architecture and data flow.

Check for geolocation redirects by manipulating request headers. Try adding or modifying X-Forwarded-For, CF-Connecting-IP, or True-Client-IP headers with IPs from different countries. If the application blindly trusts these headers for geolocation, you can bypass region restrictions.

Look at CDN and infrastructure patterns. Use tools like host, nslookup, or online DNS lookup services to see where domains resolve geographically. Check if the application uses region-specific CDN endpoints or load balancers. Different regions might have different entry points to test.

Document the regional architecture, data flows, and any region-specific features. Test each regional implementation independently for vulnerabilities. If you find an issue in one region, verify if it exists in others - sometimes a vulnerability is global, sometimes it's region-specific due to inconsistent deployments. Regional scope affects severity and remediation priority in your reports.`
  },
  'Are there mobile apps, desktop apps, or browser extensions associated with it?': {
    why: `Native applications are treasure troves for bug bounty hunters because they can be decompiled, reverse-engineered, and analyzed offline to reveal secrets that web applications keep server-side. Every mobile or desktop app you can download is a complete copy of client-side logic, API endpoints, and often sensitive data sitting on your local machine ready for analysis.

Hardcoded secrets are epidemic in mobile and desktop applications. Developers embed API keys, encryption keys, OAuth client secrets, AWS credentials, and internal API endpoints directly in the binary. Even obfuscated or encrypted, these secrets can be extracted with readily available reverse engineering tools. A single hardcoded API key can lead to full platform compromise.

Mobile and desktop apps often use different API endpoints than web applications, and these endpoints frequently have weaker security. Mobile APIs might lack rate limiting, CSRF protection, or thorough authorization checks because developers assume the app is a "trusted client". This assumption is false - you control the client and can call these APIs however you want.

Deep link handlers and custom URL schemes in mobile apps create unique attack vectors. Apps register custom schemes (appname://) that can be triggered from web pages or other apps. These handlers often have insufficient validation, leading to command injection, path traversal, or unauthorized actions. Testing deep links can uncover vulnerabilities invisible in web testing.

Browser extensions have elevated privileges and can access sensitive data across all websites the user visits. They can read cookies, intercept network traffic, modify page content, and access browser storage. A compromised or malicious extension associated with your target application can expose all user activity, not just on the target site but potentially across their entire browsing session.`,
    how: `Search the major app stores systematically. Check Apple App Store, Google Play Store, Chrome Web Store, Firefox Add-ons, and Microsoft Store. Search for the company name, product name, and variations. Download all apps you find - you'll need them for analysis even if you're primarily testing the web app.

Look for download links on the application's website. Check the homepage, footer, download page, and documentation for links to native applications. Many companies prominently advertise their mobile apps, making discovery trivial. Less obviously, check the web app's UI when logged in - many apps show "Download our mobile app" prompts or links in user settings.

Once you've downloaded mobile apps, use decompilation tools to extract the source code and resources. For Android, use jadx or apktool to decompile APK files into readable Java code. For iOS, use tools like class-dump, Hopper, or Ghidra to analyze the binary. For browser extensions, simply extract the CRX or XPI file - they're essentially ZIP archives containing readable JavaScript.

Search the decompiled code for sensitive strings immediately. Use grep or search functionality to find patterns like "api_key", "secret", "password", "token", "amazonaws.com", "//api", "https://internal", "/v1/", "/v2/". Mobile apps routinely contain API endpoints, authentication tokens, and configuration that reveals internal infrastructure.

Analyze the app's network traffic using a proxy like Burp Suite or Charles Proxy. Configure your phone or desktop to route traffic through the proxy, then use the app normally. Capture all API requests and responses. Mobile APIs often differ from web APIs and may have different authentication mechanisms or security controls.

Look for deep link handlers by examining the app manifest (AndroidManifest.xml for Android, Info.plist for iOS). These files declare custom URL schemes the app handles. Test these schemes by creating HTML pages with links like <a href="appname://action/parameter">Click</a> and see what happens when clicked from a mobile browser.

Check for hardcoded databases, configuration files, or embedded resources. Mobile apps often ship with SQLite databases, JSON configuration files, or bundled resources that contain test data, API configurations, or even production credentials. Extract and examine all resources included in the app bundle.

Cross-reference the mobile/desktop findings with the web application. If you find API endpoints in the mobile app, test them from the web context. If you find a different authentication flow, test if you can use mobile tokens on web endpoints. Often, mobile-specific APIs are accessible from web browsers and have weaker security because developers didn't expect browser-based access. Document all native applications, their API endpoints, hardcoded secrets, and security differences from the web application in your reconnaissance notes.`
  },
  'Is the web app a full product or a thin UI over APIs?': {
    why: `Understanding the application architecture reveals where business logic executes, where to focus testing efforts, and what attack vectors are most likely to succeed. The split between client and server-side logic fundamentally changes your testing approach.

Thin UI applications that rely heavily on APIs expose those APIs directly in browser network traffic, making them completely visible and testable. Every API endpoint, parameter, and response format is documented in your browser's DevTools. You can bypass all client-side validation, rate limiting, and business logic by calling APIs directly with custom requests.

Client-side validation in API-heavy apps is purely cosmetic and should never be trusted as a security control. If the UI prevents certain inputs or actions, but the API accepts them, you've found either a vulnerability or an unintended feature. Direct API testing reveals what the server actually enforces versus what the client pretends to enforce.

API-first architectures often reuse the same APIs for web, mobile, and partner integrations. An endpoint designed for mobile use might have weak authentication when called from a browser. An internal API meant for microservice communication might be accessible publicly. Understanding that you're testing an API-driven app means every endpoint is potentially accessible outside its intended context.

GraphQL applications deserve special attention because a single endpoint can expose the entire data model. GraphQL introspection can reveal every available query, mutation, field, and relationship - effectively giving you complete API documentation. Even when introspection is disabled, you can infer the schema through error messages and field guessing.`,
    how: `Open your browser's DevTools and go to the Network tab before navigating the application. As you interact with the UI - clicking buttons, filling forms, changing pages - watch what network requests fire. A thin UI over APIs will show constant API calls (typically JSON or GraphQL) with minimal full-page loads. A server-rendered app will show mostly document requests for each action.

Examine the initial page source (View Source, not Inspect Element). If you see complete content, data, and rendered HTML in the source, it's likely server-rendered. If you see minimal HTML with mostly <div id="root"> or <div id="app"> and little content, it's a client-side app that fetches everything through APIs after the JavaScript loads.

Look for API patterns in the network requests. REST APIs typically show multiple endpoints (/api/users, /api/posts, /api/comments) with HTTP verbs (GET, POST, PUT, DELETE). GraphQL shows a single /graphql endpoint with POST requests containing query bodies. WebSocket connections indicate real-time API communication.

Try accessing API endpoints directly in your browser or with curl. Copy an API URL from the Network tab, open it in a new tab, and see if it returns JSON data. If APIs respond to direct access, you can test them independently from the UI. Try modifying parameters, removing authentication headers, or changing HTTP methods.

For GraphQL applications, test for introspection immediately. Send an introspection query to the GraphQL endpoint. The query should request the __schema with its types and fields structure. If introspection is enabled, you'll receive complete schema documentation showing every available query, type, and field - essentially a complete map of the API.

Check for API documentation endpoints. Try common paths like /api/docs, /api-docs, /swagger, /api/swagger.json, /graphql, /api/v1/docs, /docs/api. Many organizations expose Swagger/OpenAPI documentation or GraphQL playgrounds that document the entire API surface area.

Examine JavaScript bundles for API endpoint references. Large client-side applications define API endpoints in JavaScript. Use DevTools Sources tab to search JavaScript files for patterns like "/api", "endpoint", "baseURL", or "fetch(". This reveals API endpoints that might not be immediately visible through UI interaction.

Test if APIs enforce authorization independently from the UI. The UI might hide certain features or data, but if the underlying API doesn't check permissions, you can access them by calling APIs directly. Remove or modify authentication headers, try other users' identifiers, and test if the API blindly trusts client-supplied parameters.

Document the architecture: Is it purely API-driven? Hybrid? Server-rendered? List all API endpoints discovered, their authentication requirements, and what data they expose. As a bug bounty hunter, prioritize API testing for thin-UI applications - the APIs are where the vulnerabilities live, not in the presentational UI layer. Focus on authorization, input validation, and business logic flaws at the API level.`
  },
  'Does the application expose public documentation or help portals?': {
    why: `Public documentation is one of the most valuable reconnaissance resources because it's officially maintained, accurate, and comprehensive - companies invest heavily in documentation to help legitimate users, which inadvertently helps security testers understand the complete attack surface.

API documentation explicitly lists every endpoint, parameter, authentication method, rate limit, and response format. This is reconnaissance gold that would take days or weeks to discover through manual testing. Swagger/OpenAPI documentation shows example requests, required headers, and error codes. This level of detail dramatically accelerates your testing and ensures you don't miss obscure endpoints.

Help portals and knowledge bases reveal business logic, edge cases, and feature interactions that aren't obvious from the UI. Articles like "How to bulk import users" or "Managing cross-workspace permissions" explain complex workflows that often have security implications. Understanding these flows helps you identify where to test for authorization bypass, injection flaws, or business logic vulnerabilities.

Developer portals sometimes contain sample code, test credentials, or sandbox environments. Tutorials might include API keys (even if labeled "example") that were copy-pasted from real keys. Test environments mentioned in docs might still be accessible. Even revoked credentials in documentation can reveal the format and structure to help brute-force or generate valid credentials.

Architecture diagrams, integration guides, and security documentation describe the application's trust model, authentication flow, and data handling. This information is normally locked away in internal documents, but customer-facing documentation often includes enough detail to understand the security architecture, identify trust boundaries, and predict where vulnerabilities might exist.`,
    how: `Start with common documentation paths on the target domain: /docs, /documentation, /api-docs, /api/docs, /help, /support, /wiki, /kb (knowledge base), /faq, /dev, /developer, /developers. Try both the main domain and common subdomains like docs.target.com, help.target.com, developers.target.com, support.target.com.

Check the website footer and navigation menus. Most applications link to their documentation prominently in the footer ("Docs", "API", "Developers", "Help Center") or in the main navigation. Follow these links and bookmark the entire documentation structure for thorough review.

Search for Swagger or OpenAPI endpoints: /swagger, /swagger.json, /swagger-ui, /api/swagger, /v1/swagger.json, /api-docs, /docs/api.json, /openapi.json. These machine-readable API specifications provide complete endpoint documentation. Even if the UI is disabled, the JSON file might still be accessible.

Look for GraphQL documentation and playgrounds. Try /graphql, /graphiql, /graphql-playground, /api/graphql. GraphQL introspection is powerful, but many organizations also provide GraphQL Playground or GraphiQL interfaces for developers. These interactive documentation tools let you explore the entire schema visually.

Review robots.txt and sitemap.xml for documentation URLs. These files often list documentation paths to help search engines index them. Check robots.txt for both allowed and disallowed paths - sometimes documentation is intentionally hidden from search engines but still publicly accessible.

Use Google dorking to find documentation: site:target.com "API documentation", site:target.com "endpoint", site:target.com "swagger", site:target.com intitle:"API". This finds documentation pages that might not be linked from the main site but are indexed by search engines.

Search external sites for the application's documentation. Many companies host documentation on GitHub Pages, ReadTheDocs, GitBook, or dedicated documentation platforms. Search for "[company name] API docs" or "[product name] developer documentation". Check the company's GitHub organization for docs repositories.

Explore help centers thoroughly. Use the search function to query security-relevant terms: "authentication", "authorization", "permissions", "roles", "API", "webhook", "integration", "admin", "security". Help articles about these topics reveal the application's security model and administrative features.

Download and read any SDK or client library documentation. If the application provides libraries for Python, JavaScript, Ruby, etc., these libraries document all available API methods, parameters, and usage examples. SDKs are essentially guaranteed accurate API documentation.

Document all discovered information systematically: list API endpoints, authentication requirements, rate limits, parameter formats, webhook configurations, and any mentioned security features. Cross-reference documentation against actual behavior - sometimes documentation is outdated or incorrect, and those discrepancies can indicate vulnerabilities or unintended features.`
  },
  'Is the app intended to be embedded or integrated into other sites?': {
    why: `Embeddable applications face unique security challenges because they must operate in untrusted parent contexts while maintaining security boundaries. This cross-origin architecture introduces entire vulnerability classes that standalone applications never encounter.

Cross-origin communication through postMessage is a common attack vector in embedded apps. When an iframe needs to communicate with its parent page, it uses postMessage, which if implemented insecurely, allows any website to send malicious messages to the embed. Poor origin validation, lack of message verification, or trusting parent-supplied data leads to XSS, authentication bypass, and data exfiltration.

CORS policies for embeddable apps are often overly permissive. To work across many customer domains, developers configure Access-Control-Allow-Origin: * or dynamically allow any origin. This breaks same-origin policy protections and allows malicious sites to make authenticated requests on behalf of users, leading to CSRF-equivalent attacks even with proper CSRF tokens.

Clickjacking protections (X-Frame-Options, CSP frame-ancestors) must be carefully balanced in embedded apps. If embedding is allowed globally, any malicious site can frame the application and trick users into performing unintended actions. If protections are too strict, the embed functionality breaks. Finding this misconfiguration - either too permissive or bypassable through allowed domains - is a common critical finding.

Embedded widgets often trust the parent page more than they should. They might read configuration from URL parameters, parent page DOM, or postMessage without validation. Malicious parent pages can manipulate these inputs to inject scripts, exfiltrate data, or trigger unintended actions within the embedded context.`,
    how: `Look for embed code snippets on the website. Check integration documentation, developer guides, or marketing pages for iframe or JavaScript embed codes. These snippets explicitly show how the application is meant to be embedded: <iframe src="https://target.com/embed/..."> or <script src="https://target.com/widget.js"></script>.

Search for WordPress plugins, Shopify apps, browser extensions, or platform integrations. If the application integrates with popular platforms, it likely has embed functionality. Check integration marketplaces (WordPress.org plugins, Shopify App Store, Zapier integrations) for the product name.

Review CORS configuration by examining API responses. Make requests to API endpoints and check Access-Control-Allow-Origin headers. If you see *, any origin, or dynamically reflected origins, the application allows cross-origin requests. Test if you can make authenticated cross-origin requests from a page you control.

Check X-Frame-Options and Content-Security-Policy frame-ancestors directives. Try embedding the application in an iframe on a test HTML page. If it loads without errors, clickjacking protections are weak or misconfigured. Check the headers to see if X-Frame-Options is absent, set to ALLOW-FROM with an overly broad list, or if CSP frame-ancestors allows unsafe origins.

Search the JavaScript code for postMessage usage. Use DevTools to search for "postMessage" and "addEventListener('message'". Read the message handlers carefully - do they validate message origin? Do they verify message content? Do they trust data from the parent page? Poor validation in message handlers is a direct path to XSS or authentication bypass.

Test postMessage security by creating a malicious parent page. Embed the application in an iframe and send various messages using iframe.contentWindow.postMessage(). Try sending authentication tokens, commands, or malicious payloads. See if you can trigger actions or extract data through unvalidated message handling.

Look for URL parameters or hash fragments that configure the embedded widget. Many embeds accept configuration via URL: /embed?token=...&config=... Test if you can inject malicious configuration, load arbitrary content, or bypass security checks through manipulated parameters.

Check for integration documentation describing webhooks, callbacks, or OAuth redirect URIs. Embeddable apps often support webhooks for events or OAuth for authentication. Test if webhook URLs are validated, if redirect URIs can be manipulated, and if the integration points have proper authorization checks.

Review third-party integration partners. If the application advertises integration with many platforms, each integration is a potential security boundary to test. Check if integrations share credentials, if API keys for integrations have excessive permissions, and if integration flows have proper security validation.

Document all embed mechanisms, their security configurations, and identified weaknesses. Test embedding the application in different contexts - benign sites, malicious sites, sites with mixed content. Evaluate if the embed maintains security boundaries or if the untrusted parent context can compromise the embedded application. Embeddable app vulnerabilities often qualify as critical findings because they affect all users across all sites where the embed is used.`
  },
  'What frontend framework is used?': {
    why: `Identifying the frontend framework unlocks an entire category of targeted attacks and testing strategies. Each major framework (React, Vue, Angular, Svelte) has documented security considerations, common implementation mistakes, and framework-specific vulnerability patterns.

Framework-specific XSS vectors are real and exploitable. React's dangerouslySetInnerHTML, Vue's v-html directive, and Angular's bypassSecurityTrust methods are all intentional bypass mechanisms that developers often misuse. When you know the framework, you know exactly what dangerous patterns to search for in the source code and what payloads to test.

CVE databases are full of framework and framework-library vulnerabilities. Knowing you're testing a React application means you can check if they're using vulnerable versions of React itself, react-router, redux, or any of the thousands of React-specific libraries. Many organizations fail to update frontend dependencies, leaving known vulnerabilities exploitable for years.

Build processes and source maps vary by framework. React apps built with Create React App have different artifact structures than Next.js applications. Understanding the framework helps you locate source maps (if exposed), understand the file structure, and identify development vs. production builds. Source maps can expose the entire unminified, commented source code - a goldmine for finding vulnerabilities.

Framework documentation is your friend. When you identify Vue.js, you can read Vue's security guide to understand common pitfalls developers make, then look for those exact mistakes in the target application. Framework knowledge turns generic testing into targeted hunting.`,
    how: `Open your browser's Developer Tools and look for framework-specific debugging tools. React applications often trigger "React Developer Tools" to detect React on the page. Vue applications similarly trigger Vue DevTools. These browser extensions auto-detect the framework, making identification instant.

Examine the page source (View Source, not Inspect Element) for framework indicators. Look for distinctive patterns: React applications often have <div id="root"> or data-reactroot attributes. Vue apps use v-* attributes like v-if, v-for, v-model in their templates. Angular apps have ng-* attributes. These attributes are framework signatures.

Inspect loaded JavaScript files in the Network tab. Framework libraries have recognizable filenames: react.js, vue.runtime.js, angular.min.js. Even when minified and bundled, webpack often includes module comments or the framework name in bundle files. Look for patterns like /*! React */ or vendor chunks named vendor.react.chunk.js.

Check meta tags and HTML comments. Some applications helpfully include generator meta tags like <meta name="generator" content="Next.js">. Build tools sometimes leave comments in the HTML like <!-- Built with Vue.js -->. These are gift-wrapped framework identifications.

Use the browser extension Wappalyzer or BuiltWith which automatically detect frontend frameworks, libraries, and their versions. While not 100% accurate, they provide quick identification and often detect supporting libraries you might miss manually.

Look for framework-specific file structures in the DevTools Sources tab. Next.js applications have distinctive _next/ directories. Nuxt.js has _nuxt/. Create React App follows predictable patterns in static/js/. These file structures are as reliable as fingerprints.

Once identified, document the framework and check its version. Search JavaScript files for version strings like React@17.0.2 or look at library filenames that include versions. Search the known vulnerabilities database (CVE, Snyk, npm audit) for that framework and version. This creates an immediate testing checklist of known issues to verify.`
  },
  'Is the app a Single Page Application?': {
    why: 'SPAs load all code upfront, often exposing routes, API endpoints, and logic in bundled JavaScript. They rely heavily on client-side routing and state management, which can lead to authorization bypass if not properly validated server-side. Source maps may expose original code.',
    how: 'Check if navigation changes the URL without full page reloads. Look for large JavaScript bundles, client-side routing libraries (React Router, Vue Router), and single initial HTML response. Monitor network tab—SPAs make API calls rather than requesting new HTML pages.'
  },
  'Is server-side rendering used?': {
    why: 'SSR affects where business logic executes, how data is hydrated, and where vulnerabilities might exist. SSR apps may have serialization issues, expose server-side code, or have different XSS attack vectors. Understanding rendering helps identify where to look for vulnerabilities.',
    how: 'View page source (not inspect element) and check if content is present in initial HTML. Look for SSR framework indicators (Next.js, Nuxt, Gatsby). Check for __NEXT_DATA__ or similar hydration payloads. Test if disabling JavaScript shows full content.'
  },
  'What backend language(s) are implied?': {
    why: 'Backend languages have different vulnerability patterns, default configurations, and common frameworks. Knowing the language helps target language-specific attacks (e.g., Java deserialization, PHP type juggling, Python SSTI) and identify framework-specific security issues.',
    how: 'Check HTTP headers (X-Powered-By, Server), error messages, file extensions in URLs (.php, .jsp, .aspx), session cookie names (PHPSESSID, JSESSIONID), and framework indicators. Look at job postings, GitHub repos, or use Wappalyzer/BuiltWith tools.'
  },
  'Is the backend REST, GraphQL, or mixed?': {
    why: 'GraphQL and REST have different security models. GraphQL may expose entire schema via introspection, allow complex nested queries (DoS), and have field-level authorization issues. REST APIs may have IDOR, mass assignment, or verb tampering vulnerabilities.',
    how: 'Use browser DevTools to check API requests. GraphQL typically uses POST to /graphql endpoint with query bodies. Try GraphQL introspection queries. REST uses multiple endpoints with HTTP verbs. Look for /api/, /v1/, /rest/ patterns and OpenAPI/Swagger docs.'
  },
  'Are API versioning patterns present?': {
    why: 'Multiple API versions often coexist, and older versions may have unpatched vulnerabilities or weaker security controls. Version differences can reveal how security evolved and where legacy issues persist. Newer versions might expose more functionality.',
    how: 'Look for /v1/, /v2/, /api/v1/ in URLs, X-API-Version headers, or version parameters. Try incrementing/decrementing version numbers. Check if authentication differs between versions. Review API documentation for version-specific features and deprecation notices.'
  },
  'Are build tools identifiable from assets?': {
    why: 'Build tool artifacts (webpack, Vite, Parcel) can expose source maps, reveal project structure, leak environment variables, and show unminified code. Build tool versions may have known vulnerabilities. Configuration files may be exposed.',
    how: 'Look for .map files in DevTools sources, webpack:// schemes, comment headers in JS files mentioning build tools, or chunk naming patterns. Check for webpack.config.js, vite.config.js, or other config files at common paths. Examine bundle structure.'
  },
  'Are framework or library versions exposed?': {
    why: 'Known vulnerable versions can be directly exploited. Version information helps target specific CVEs, find public exploits, and identify security patches that weren\'t applied. Even patched versions reveal technology choices and potential compatibility issues.',
    how: 'Check JavaScript library files for version comments, use Wappalyzer/Retire.js, look at package.json if exposed, examine HTTP headers, check generator meta tags, look for version strings in error messages, or use browser DevTools to inspect loaded libraries.'
  },
  'Are deprecated or end-of-life libraries in use?': {
    why: 'EOL libraries don\'t receive security updates, have known unpatched vulnerabilities, and signal technical debt. They\'re high-value targets since exploits are public and patches won\'t be released. They may indicate overall poor security posture.',
    how: 'Use Retire.js, Snyk, or npm audit concepts. Check library versions against EOL databases. Look for old jQuery, Angular.js, Bootstrap 3, or other legacy frameworks. Check release dates of detected versions against current dates.'
  },
  'Are custom client-side frameworks present?': {
    why: 'Custom frameworks often lack security reviews, have undiscovered vulnerabilities, and may implement security controls incorrectly. They\'re not battle-tested like popular frameworks. Understanding custom code reveals unique attack vectors not found elsewhere.',
    how: 'Look for non-standard JavaScript patterns, custom namespaces, proprietary library names, or company-specific framework indicators. Review main JavaScript bundles for custom classes/modules. Check for unusual coding patterns or bespoke state management.'
  },
  'Is the application behind a CDN?': {
    why: 'CDNs cache content and may serve stale data, including sensitive information. They can be bypassed to reach origin servers, may have cache poisoning vulnerabilities, and affect how security headers are applied. CDN misconfigurations can expose origin IPs.',
    how: 'Check for CDN headers (CF-Ray, X-CDN, X-Cache), lookup DNS/IP addresses (Cloudflare, Akamai, Fastly ranges), look for CDN-specific cookies, use tools like host command or SecurityTrails, and check if response headers indicate caching behavior.'
  },
  'Which CDN or edge provider is used?': {
    why: 'Different CDNs have different security features, bypass techniques, and configuration options. Some CDNs have known vulnerabilities or misconfigurations. Knowing the provider helps identify provider-specific attack vectors (e.g., Cloudflare worker bypasses).',
    how: 'Check HTTP headers (CF-Ray for Cloudflare, X-Akamai, X-Fastly), DNS CNAME records, SSL certificate authorities, IP ranges (whois), and distinct header patterns. Use online tools like CDNPlanet or SecurityTrails to identify providers.'
  },
  'What server software is observable?': {
    why: 'Server software versions have known CVEs, default configurations, and predictable behaviors. Knowing the server helps target version-specific exploits, understand server-side capabilities, and identify misconfigurations. Some servers have distinct vulnerability patterns.',
    how: 'Check Server and X-Powered-By headers, error pages (default error pages reveal server type), HTTP fingerprinting, server behavior differences (header ordering), and timing differences. Use tools like httprint or Wappalyzer.'
  },
  'Is a load balancer or reverse proxy in use?': {
    why: 'Load balancers can be used to bypass security controls, may have request smuggling vulnerabilities, affect session handling, and create inconsistencies between frontend and backend request interpretation. They may expose internal IP ranges or hostnames.',
    how: 'Look for multiple backend servers in headers/cookies, check for X-Forwarded headers, HAProxy cookies, or session stickiness patterns. Try cache-based detection, multiple requests to observe different backends, or header inconsistencies suggesting intermediary processing.'
  },
  'Is the app hosted in a public cloud?': {
    why: 'Cloud hosting exposes metadata services (SSRF to 169.254.169.254), may use default IAM roles, and can have storage bucket misconfigurations. Cloud-specific vulnerabilities exist (AWS confused deputy, Azure AD issues). Cloud IDs may leak in URLs or errors.',
    how: 'Check IP ranges against cloud provider blocks (AWS, GCP, Azure), look for cloud-specific SSL certificates, check for S3 bucket URLs, Azure Blob storage, GCS URLs, or cloud-specific headers. Use tools like cloudfail or SecurityTrails.'
  },
  'Can the cloud provider be identified?': {
    why: 'Knowing the provider helps target cloud-specific vulnerabilities, understand available services, identify metadata endpoints to attack via SSRF, and recognize cloud-native security controls. Different clouds have different security models and common misconfigurations.',
    how: 'Check IP address ranges (WHOIS, ASN lookups), SSL certificates (AWS Certificate Manager, Google Trust Services), domain patterns (compute.amazonaws.com, cloudapp.net, cloudfunctions.net), and HTTP headers revealing cloud origin.'
  },
  'Are multiple services hosted on the same domain?': {
    why: 'Multiple services on one domain can create trust boundary issues, cookie sharing problems, and privilege escalation opportunities. A vulnerability in one service can compromise others through shared origin. Session cookies may be overly scoped.',
    how: 'Explore different paths (/blog, /shop, /api, /admin), look for distinct functionality areas, check for different tech stacks in different sections, monitor cookies for different paths, or observe architectural inconsistencies suggesting multiple applications.'
  },
  'Is virtual hosting used?': {
    why: 'Virtual hosting can lead to host header injection vulnerabilities, password reset poisoning, cache poisoning, and routing issues. The server may respond differently to different Host headers, potentially exposing internal services or bypassing security controls.',
    how: 'Try different Host headers while keeping the same IP, check Server Name Indication (SNI) in SSL, look for multiple domains on the same IP (reverse DNS, certificate SANs), and test if the app behaves differently with modified Host headers.'
  },
  'Are containerization or serverless hints present?': {
    why: 'Containerized apps may expose Docker/Kubernetes APIs, have escape vulnerabilities, or reveal orchestration details. Serverless apps have cold start behaviors, limited execution time, and function-based architecture. Both have unique security models and attack vectors.',
    how: 'Look for container-specific paths (/proc/self/cgroup), AWS Lambda indicators in URLs or headers, cold start timing patterns, short-lived connections, or references to container orchestration. Check for exposed /.dockerenv or /run/secrets/kubernetes.io.'
  },
  'Are internal hostnames or regions leaked in responses?': {
    why: 'Internal hostnames reveal network topology, naming conventions, and infrastructure details useful for social engineering. Region information helps identify where data is stored (compliance issues) and may expose staging/dev environments. These leaks aid reconnaissance.',
    how: 'Check HTTP headers (Via, X-Forwarded, X-Real-IP), error messages, stack traces, redirect URLs, email addresses in responses, SSL certificate SANs, and timing headers. Look for internal TLDs (.local, .internal, .corp) or private IP addresses in responses.'
  },
  'Is HTTPS enforced everywhere?': {
    why: 'Mixed content or available HTTP endpoints allow man-in-the-middle attacks, session hijacking, and credential theft. Even single unencrypted request can leak sensitive tokens or cookies. HTTPS enforcement is foundational security that affects all other controls.',
    how: 'Try accessing HTTP version of URLs, check if HTTP redirects to HTTPS, look for mixed content warnings in DevTools, test if cookies are set over HTTP, and verify all resources (images, scripts, APIs) load over HTTPS.'
  },
  'Is HSTS enabled?': {
    why: 'Without HSTS, the first request can be intercepted before HTTPS redirect occurs (SSL stripping attacks). HSTS ensures browsers only connect via HTTPS, preventing downgrade attacks. HSTS preload provides even stronger protection but requires careful planning.',
    how: 'Check for Strict-Transport-Security header in HTTPS responses, verify max-age value, check for includeSubDomains directive, and look up domain on HSTS preload list. Test if HTTP request automatically upgrades without server redirect.'
  },
  'Which TLS versions are supported?': {
    why: 'Old TLS versions (1.0, 1.1) have known vulnerabilities (BEAST, POODLE) and should be disabled. Supporting outdated protocols allows downgrade attacks. Modern apps should require TLS 1.2+ with secure cipher suites.',
    how: 'Use SSL Labs, testssl.sh, nmap with ssl-enum-ciphers script, or openssl s_client with -tls1, -tls1_1, -tls1_2, -tls1_3 flags. Check browser DevTools Security tab for protocol version.'
  },
  'Are weak cipher suites accepted?': {
    why: 'Weak ciphers enable decryption of encrypted traffic, man-in-the-middle attacks, and forward secrecy issues. Export-grade ciphers and RC4 have known attacks. Modern apps should only accept strong AEAD ciphers with forward secrecy.',
    how: 'Use SSL Labs, testssl.sh, nmap ssl-enum-ciphers, or openssl s_client with -cipher flag. Look for NULL, EXPORT, DES, RC4, MD5 ciphers. Check for forward secrecy (ECDHE, DHE key exchange).'
  },
  'Is HTTP/2 or HTTP/3 used?': {
    why: 'HTTP/2 introduces request smuggling variants, header compression attacks (CRIME), and stream multiplexing issues. HTTP/3 (QUIC) has different security properties. Understanding the protocol helps identify protocol-specific vulnerabilities.',
    how: 'Check browser DevTools Network tab protocol column, look for HTTP/2 headers (:method, :path), check server headers advertising h2/h3, use curl with --http2 or --http3 flags, or use online HTTP/2 test tools.'
  },
  'Are cookies marked Secure?': {
    why: 'Cookies without Secure flag can be transmitted over HTTP, allowing session hijacking via network sniffing or man-in-the-middle attacks. Even if HTTPS is enforced, absence of Secure flag creates attack opportunities during misconfigurations.',
    how: 'Check DevTools Application/Storage tab for cookie attributes, look for Secure flag in Set-Cookie headers, test if cookies are sent over HTTP connections, and review all cookies (session, CSRF, tracking) for proper flags.'
  },
  'Are cookies marked HttpOnly?': {
    why: 'Without HttpOnly, cookies can be stolen via XSS attacks using JavaScript. HttpOnly prevents client-side scripts from accessing cookies, limiting impact of XSS. Session cookies especially should always be HttpOnly.',
    how: 'Check DevTools Application/Storage tab, look for HttpOnly flag in Set-Cookie headers, try accessing cookies via document.cookie in browser console, and verify all sensitive cookies have HttpOnly set.'
  },
  'Is SameSite set on cookies?': {
    why: 'SameSite prevents CSRF attacks by controlling when cookies are sent with cross-site requests. Without SameSite, applications rely solely on CSRF tokens, which can be bypassed. SameSite=Strict provides strongest protection but may break legitimate flows.',
    how: 'Check Set-Cookie headers for SameSite=Strict, SameSite=Lax, or SameSite=None attributes. Test cross-site request behavior. Review authentication and session cookies particularly. Check if cookies require SameSite=None with Secure.'
  },
  'Are authentication cookies scoped to subdomains?': {
    why: 'Overly broad cookie scope (Domain=.example.com) means a vulnerability on any subdomain can steal cookies for all subdomains. Subdomain takeovers become more critical. Cookie scope should be as narrow as possible for the application needs.',
    how: 'Check Set-Cookie headers for Domain attribute, test if cookies from one subdomain are sent to others, look for leading dot in domain (.example.com vs example.com), and map which subdomains share session cookies.'
  },
  'Are multiple domains involved in session handling?': {
    why: 'Cross-domain session handling creates CSRF opportunities, cookie scope issues, and trust boundary problems. SSO implementations may have token leakage or replay issues. Multiple domains complicate secure session management.',
    how: 'Monitor network traffic during login/logout across domains, check for token passing in URLs or postMessage, look for CORS configurations allowing credentials, observe redirects and token exchanges, and map complete authentication flow.'
  },
  'Is a Web Application Firewall present?': {
    why: 'WAFs can block attacks but also provide false sense of security. Knowing WAF presence helps understand monitoring capabilities, may indicate vulnerability awareness, and suggests bypass techniques to test. WAF rules can sometimes be evaded.',
    how: 'Try common payloads and look for generic block pages, check for WAF-specific headers (X-WAF, X-Firewall), look for timing differences on attack payloads, test with purposely malicious requests, or use wafw00f tool.'
  },
  'Can the WAF vendor be identified?': {
    why: 'Different WAFs have different bypass techniques, known weaknesses, and signature patterns. Vendor-specific bypasses exist. Understanding the WAF helps craft payloads that evade detection and prioritize testing areas with weaker coverage.',
    how: 'Check HTTP headers (X-WAF-Vendor, X-CDN-Request-ID), analyze block pages for vendor branding, use wafw00f tool, test vendor-specific bypass techniques, or check DNS/IP ranges for known WAF providers.'
  },
  'Is bot detection or fingerprinting in use?': {
    why: 'Bot detection affects automated testing, may block security scanners, and can create false negatives in testing. Understanding detection methods helps craft stealthier attacks and identify normal vs. suspicious behavior patterns.',
    how: 'Use automated tools and observe blocks, check for bot detection services (Akamai Bot Manager, DataDome), look for fingerprinting JavaScript, test with Selenium vs curl, observe challenges or CAPTCHAs, and check for device fingerprinting libraries.'
  },
  'Is rate limiting observable?': {
    why: 'Rate limits affect brute force attacks, enumeration, and fuzzing speed. They may indicate security awareness or high-value endpoints. Bypassing rate limits (IP rotation, distributed attacks) may be necessary for comprehensive testing.',
    how: 'Send many rapid requests and observe for 429 responses, timing delays, or temporary blocks. Check X-RateLimit headers, test different endpoints for different limits, try IP rotation, and note if limits are per-IP, per-session, or per-account.'
  },
  'Is CAPTCHA used anywhere in the app?': {
    why: 'CAPTCHA prevents automated abuse but may have bypass vulnerabilities, implementation weaknesses, or be selectively applied. Understanding CAPTCHA coverage helps identify areas vulnerable to automation and bot attacks.',
    how: 'Look for CAPTCHA on login, registration, password reset, search, API calls, or comment forms. Check for Google reCAPTCHA, hCaptcha, or custom implementations. Note when CAPTCHA appears (always, after failures, on suspicious behavior).'
  },
  'Is CAPTCHA conditional or global?': {
    why: 'Conditional CAPTCHA can be bypassed by avoiding trigger conditions. Global CAPTCHA affects all testing. Understanding triggers helps identify what behavior is considered suspicious and how to perform testing without triggering protections.',
    how: 'Test with clean IP vs VPN, slow vs fast requests, after multiple failures vs first attempt, authenticated vs anonymous. Note what triggers CAPTCHA: velocity, IP reputation, user agent, behavioral signals.'
  },
  'Are request challenges used (JS challenges, proof-of-work)?': {
    why: 'JS challenges and proof-of-work add client requirements that automated tools may not handle. They prevent simple scripted attacks but can be bypassed with proper browser automation. Understanding challenges helps adapt testing tools.',
    how: 'Look for JavaScript that must execute before requests succeed, computational challenges in responses, timing requirements, or browser-specific APIs being checked. Use headless browsers and compare to curl results.'
  },
  'Are IP-based restrictions present?': {
    why: 'IP restrictions may hide functionality from public testing, indicate geo-restrictions, or separate internal/external access. Bypassing IP restrictions (via X-Forwarded-For, proxies, VPNs) may reveal additional attack surface.',
    how: 'Test from different geographic locations/VPNs, try X-Forwarded-For and other proxy headers with internal IPs (127.0.0.1, 192.168.x.x), check for geo-blocking patterns, and note if certain endpoints return 403 from specific IPs.'
  },
  'Does behavior differ for authenticated users?': {
    why: 'Different behavior can indicate privilege escalation opportunities, unprotected endpoints for unauthenticated users, or authorization bypass issues. Some vulnerabilities only appear in authenticated context while others only appear pre-auth.',
    how: 'Test same endpoints authenticated vs unauthenticated, compare API responses, check rate limits, CAPTCHA, and error messages. Look for endpoints that require auth but don\'t verify authorization. Map functionality accessible to each role.'
  },
  'Are automated clients treated differently?': {
    why: 'Differential treatment can be bypassed but also indicates security monitoring. Headless browsers may be detected and blocked. Understanding detection helps adapt tools. Cloaking may hide vulnerabilities from scanners.',
    how: 'Compare curl vs browser requests, Selenium vs manual browsing, check User-Agent effects, test WebDriver detection, look for headless browser detection (navigator.webdriver), and compare headers/behavior of different clients.'
  },
  'Is authentication required to access core functionality?': {
    why: `Understanding authentication requirements shapes your entire testing strategy. Applications with significant unauthenticated functionality have a larger public attack surface, while authentication-gated apps concentrate risk in session management, authorization, and authentication bypass vulnerabilities.

Unauthenticated endpoints are often overlooked by both developers and security testers because everyone assumes the "important" stuff requires login. This assumption is dangerous. Some applications expose APIs, data queries, or even administrative functions without proper authentication checks. These endpoints can be discovered through forced browsing, API documentation, or JavaScript analysis.

The authentication boundary defines trust assumptions. When you know what's public vs. private, you can test the boundary itself. Try accessing authenticated endpoints with no credentials, expired tokens, or another user's session. Many IDOR (Insecure Direct Object Reference) vulnerabilities exist at this boundary where developers check IF you're logged in but not WHOSE data you're accessing.

Applications with optional authentication often have inconsistent security controls. Public features might lack rate limiting, CSRF protection, or input validation that developers only implemented for authenticated areas. These inconsistencies create vulnerability opportunities - you might find XSS in a public contact form that's not present in authenticated areas because different validation rules apply.

Mapping public vs. private functionality reveals the application's security model and attack priorities. If 90% of functionality requires authentication, focus on authentication bypass, session management, and authorization bugs. If substantial functionality is public, prioritize input validation, injection attacks, and business logic flaws in unauthenticated areas.`,
    how: `Begin by browsing the entire application without creating an account or logging in. Document every feature, form, search function, and endpoint you can access. Take notes on what data is visible, what actions are possible, and what restrictions you encounter. This establishes your unauthenticated baseline.

Create an account and log in, then repeat your exploration. The difference between these two experiences reveals the authentication boundary. Features that appear only after login are authenticated. But don't trust the UI - some authenticated features might be accessible if you know the direct URL or API endpoint.

Use your browser's DevTools to capture all network requests during both sessions. Export authenticated session requests and try replaying them without authentication cookies or tokens. Remove the Authorization header, delete session cookies, or use a different browser/incognito window. If requests succeed without authentication, you've found an authentication bypass.

Look for predictable URL patterns that suggest authenticated endpoints: /dashboard, /admin, /api/user, /account, /settings, /profile. Try accessing these URLs directly without logging in. Many applications fail to enforce authentication at every endpoint, especially on API routes that developers assumed were "protected" by the UI.

Test APIs independently from the web interface. Applications often have different authentication enforcement between their web UI and API layer. The UI might block unauthenticated access while the underlying API accepts requests. Use tools like Postman or curl to call APIs directly, removing or modifying authentication headers.

Check for mobile app APIs if the application has a mobile version. Mobile APIs sometimes have weaker authentication requirements or different endpoints that bypass web authentication checks. Inspect mobile traffic using a proxy like Burp Suite to identify these endpoints.

Document your findings in a clear authentication map: list all unauthenticated endpoints, all authenticated endpoints, and any endpoints with ambiguous or inconsistent authentication. Prioritize testing endpoints that should be authenticated but aren't, or vice versa. These mismatches often indicate vulnerabilities.`
  },
  'What authentication methods are supported?': {
    why: 'Multiple auth methods mean multiple attack surfaces. Each method (password, OAuth, SAML, magic link, SMS) has distinct vulnerabilities. Weaker methods can undermine stronger ones. Account linking between methods can have logic flaws.',
    how: 'Check login page for options, look for social login buttons, test for API key authentication, check for passwordless flows, review documentation for authentication options, and try different login paths.'
  },
  'Are third-party IdPs used?': {
    why: 'Third-party IdPs introduce OAuth/OIDC vulnerabilities, redirect issues, and trust relationships. Implementation flaws in OAuth flows are common. IdP selection may reveal target user base and business relationships.',
    how: 'Look for "Login with Google/Microsoft/GitHub" buttons, check OAuth redirect URIs, observe authorization flows in network traffic, test for OAuth misconfiguration (open redirects in redirect_uri), and review authentication flow.'
  },
  'Is OAuth or OIDC used?': {
    why: 'OAuth/OIDC have complex flows with many known vulnerability patterns: redirect URI manipulation, token leakage, CSRF, scope issues, and implementation flaws. Understanding OAuth version and flow type is critical for testing.',
    how: 'Monitor authentication flow for /oauth/, /authorize, /token endpoints, check for JWT tokens, observe code/token exchanges, look for state parameter (CSRF protection), review redirect_uri handling, and test PKCE usage.'
  },
  'Are multiple login methods available?': {
    why: 'Multiple paths to authentication mean multiple attack surfaces. Account enumeration may work on one but not others. Weaker methods (magic links, SMS) can bypass stronger ones (password+MFA). Account linking flaws are common.',
    how: 'Test email/password, social logins, magic links, SMS codes, SAML SSO. Check if same account works across methods, test account linking/unlinking, look for method preference or fallbacks, and identify the weakest authentication path.'
  },
  'Is MFA supported?': {
    why: 'MFA significantly raises security bar but implementation matters. Bypasses, backup codes, device trust, and recovery flows may have weaknesses. MFA presence indicates higher security maturity but also higher value targets.',
    how: 'Check account settings for MFA options, look for 2FA setup flow, test for TOTP, SMS, or hardware key support, try logging in with and without MFA, and check if MFA can be bypassed via API endpoints.'
  },
  'Is MFA optional or mandatory?': {
    why: 'Optional MFA means users can be convinced to disable it (social engineering) or may never enable it. Mandatory MFA is stronger but recovery and new device flows become critical attack vectors. Account recovery may bypass MFA.',
    how: 'Create test accounts and check if MFA is required or optional. Try completing actions without MFA enabled. Check if certain roles require MFA. Test if API access bypasses MFA requirements.'
  },
  'Are long-lived sessions used?': {
    why: 'Long sessions increase risk if tokens are stolen. "Remember me" functionality often uses long-lived tokens with different security properties. Token refresh mechanisms may have vulnerabilities. Session duration affects attack windows.',
    how: 'Note session timeout duration, test "remember me" checkbox, examine token expiry claims (JWT exp), test if sessions persist across browser restarts, and check if different actions have different timeout requirements.'
  },
  'Are refresh tokens observable client-side?': {
    why: 'Client-side refresh tokens can be stolen via XSS and used to maintain persistent access. Refresh tokens should be HttpOnly or stored securely. Token refresh logic may have race conditions or reuse issues.',
    how: 'Check localStorage, sessionStorage, cookies for refresh tokens, look for /refresh or /token endpoints, monitor token refresh requests in network tab, examine JWT payloads, and test if tokens can be replayed.'
  },
  'Are authentication flows shared across domains?': {
    why: 'Cross-domain authentication creates token leakage opportunities, postMessage vulnerabilities, and CORS issues. Shared sessions across domains expand impact of XSS. SSO implementations may have redirect or token passing flaws.',
    how: 'Monitor authentication across subdomains, check for token passing in URLs or postMessage, observe CORS policies with credentials, test cross-domain session sharing, and map complete SSO flow including redirects.'
  },
  'Are multiple user roles visible?': {
    why: 'Multiple roles mean complex authorization logic and potential privilege escalation paths. Role-based testing is critical. Admin/moderator roles are high-value targets. Understanding role hierarchy helps target testing.',
    how: 'Register multiple accounts with different roles, check user settings for role indicators, look for admin interfaces, observe different UI/functionality for different users, test role-specific endpoints, and check for role enumeration.'
  },
  'Are role distinctions observable in the UI?': {
    why: 'Visible role distinctions help map authorization boundaries but may be only UI-level. Server-side enforcement must be verified. Role indicators can help with account enumeration. Hidden UI elements may still have accessible API endpoints.',
    how: 'Compare UI for different user types, look for role badges or indicators, check for disabled vs hidden features, test if API endpoints enforce same restrictions as UI, and try accessing admin UI as normal user.'
  },
  'Is the application multi-tenant?': {
    why: `Multi-tenancy is one of the highest-risk architectural patterns in modern web applications because a single vulnerability in tenant isolation can expose data from hundreds or thousands of organizations. When one customer's data leaks to another customer, it's a critical, company-ending security incident.

Tenant isolation failures are a goldmine for bug bounty hunters because they're consistently rated as critical severity. If you can access another organization's data, you've bypassed the entire authorization model. Companies pay top dollar for these findings because the business impact is enormous - regulatory fines, customer loss, legal liability, and reputation damage all stem from tenant isolation bugs.

Multi-tenant architectures create specific vulnerability patterns. Look for tenant identifiers (org_id, workspace_id, account_id) in URLs, API requests, or tokens. These identifiers become IDOR testing opportunities - what happens if you change org_id=123 to org_id=124? Many applications check that you're authenticated but fail to verify you belong to the organization you're requesting data from.

Invitation and member management features are frequent vulnerability sources in multi-tenant apps. Can you invite yourself to another organization? Can you escalate privileges within an organization? Can you remain in an organization after being removed? These edge cases in tenant membership logic often expose critical flaws.

Shared resources between tenants introduce additional complexity. If users can share documents or collaborate across organizations, the permission model becomes significantly more complex. Cross-tenant sharing is exactly where developers make mistakes - allowing too much access, failing to revoke access properly, or creating privilege escalation paths through shared objects.`,
    how: `Start by creating multiple accounts in different organizations or workspaces. Most multi-tenant SaaS applications offer free trials or free tiers, allowing you to create distinct tenant environments for testing. You need at least two organizations you control to effectively test tenant isolation.

Once you have multiple tenant accounts, systematically compare the URLs, API requests, and cookies between them. Log in to Organization A and capture all network traffic. Then log in to Organization B and capture that traffic. Look for tenant-identifying parameters that appear consistently: org_id, workspace_id, account_id, tenant_id, company_id, or similar.

Test the most obvious IDOR pattern: try using Organization A's authentication while requesting Organization B's resources. Change the org_id parameter in API calls, modify workspace identifiers in URLs, or swap tenant_ids in request bodies. A surprising number of applications only verify authentication (are you logged in?) without verifying authorization (are you allowed to access this tenant's data?).

Examine JWT tokens or session data for tenant context. Decode JWT tokens (they're Base64-encoded JSON) and look for tenant identifiers in the payload. If tenant ID is in the token, test if the server validates that claim against the requested resource, or if it blindly trusts the org_id parameter in your request.

Test invitation and membership flows comprehensively. Try inviting yourself to your test organizations, accepting invitations, removing users, changing roles, and leaving organizations. At each step, test if you can access old organizations after leaving, if you can escalate your role, or if you can access resources during the invitation acceptance process before permissions are properly established.

Look for public identifiers that reveal tenant structure. Can you enumerate organization IDs? Are organization names in URLs or API responses? Sequential IDs or predictable naming patterns make it easy to identify other tenants to target in your testing.

Test cross-tenant features particularly carefully if they exist. If users can share documents, invite guests, or collaborate across organizations, map the entire permission model. Test edge cases: What if a shared document is deleted from one tenant? What if a user is removed from one organization but was viewing shared content? These state transitions often have bugs.

Document all tenant identifiers you discover and create a checklist of every endpoint that accepts tenant parameters. Systematically test each endpoint for authorization bypass. This methodical approach often uncovers critical vulnerabilities that ad-hoc testing misses.`
  },
  'Are organizations, teams, or workspaces present?': {
    why: 'These grouping mechanisms introduce authorization boundaries that must be enforced. Switching organizations may reveal privilege escalation. Invitations and member management have common vulnerabilities (privilege escalation, invitation bypass).',
    how: 'Check for organization/workspace switchers, test invitation flows, try accessing resources from wrong org, look for org identifiers in requests, test adding/removing members, and verify org-level vs user-level permissions.'
  },
  'Are user identifiers exposed client-side?': {
    why: 'Exposed user IDs enable user enumeration, IDOR attacks, and targeted attacks. Sequential IDs reveal user count and growth. UUIDs are better but may still leak information. IDs in APIs often indicate other ID-based vulnerabilities.',
    how: 'Check profile URLs, API responses, HTML source, data attributes, and JavaScript for user IDs. Test if incrementing/changing user IDs accesses other users. Look for user_id, uid, id parameters in requests.'
  },
  'Are object identifiers exposed globally?': {
    why: 'Exposed object IDs (posts, files, messages) are primary IDOR targets. Predictable IDs make enumeration easy. Object IDs in URLs enable forced browsing. GUIDs are safer but authorization must still be verified.',
    how: 'Note IDs in URLs (/document/123, /invoice/456), API responses, and form fields. Test if changing IDs accesses other objects. Check for predictable patterns (sequential, timestamp-based). Try other users\' object IDs.'
  },
  'Are shared resources visible?': {
    why: 'Shared resources have complex permission models (owner, editor, viewer) prone to authorization bugs. Permission changes may not propagate correctly. Public/private transitions and share link vulnerabilities are common.',
    how: 'Create shared documents/files/projects, test different permission levels, try accessing shared resources after permissions revoked, test share links for unintended access, and verify permission enforcement on all operations (read, write, delete).'
  },
  'Are admin interfaces exposed?': {
    why: 'Admin interfaces are high-value targets with powerful functionality. They may have weaker authentication, be on different paths, or be unintentionally exposed. Finding admin panels is a major win for attackers.',
    how: 'Try common admin paths (/admin, /administrator, /backend, /panel), check robots.txt, use directory brute-forcing, look for admin links in source, test if removing auth allows admin access, and check for admin subdomains.'
  },
  'Are feature flags visible client-side?': {
    why: 'Feature flags may enable hidden functionality, bypass restrictions, access beta features, or reveal roadmap. Flags may have insufficient authorization checks. Manipulating flags client-side might enable unauthorized features.',
    how: 'Check localStorage/cookies for flags, look for feature flag services (LaunchDarkly, Split), examine JavaScript for flag checks, try manipulating flag values, and observe if new features/UI appear. Look for /features or /config endpoints.'
  },
  'Are permissions enforced centrally or per-service?': {
    why: 'Distributed permission enforcement can be inconsistent, with some services missing authorization checks. Centralized enforcement is stronger but single point of failure. Microservices often have inconsistent authorization.',
    how: 'Test same resource across different endpoints/services, call APIs directly vs through UI, check if different microservices enforce same permissions, observe authorization patterns in responses, and test for authorization bypass on different paths to same resource.'
  },
  'What third-party scripts are loaded?': {
    why: 'Third-party scripts have full page access and can steal data, inject malware, or be compromised (supply chain attacks). They expand attack surface and create dependencies. Some may have known vulnerabilities.',
    how: 'Use DevTools Network tab, view page source, check CSP headers for script sources, use browser extensions like LibraryDetector, examine script src attributes, and look for analytics, ads, CDN-loaded libraries, and widgets.'
  },
  'Are analytics platforms present?': {
    why: 'Analytics may leak sensitive data (PII, search queries, internal URLs) to third parties. Analytics scripts have page access. Some analytics platforms have had breaches or vulnerabilities. They may track user behavior in detail.',
    how: 'Look for Google Analytics, Mixpanel, Segment, Amplitude scripts in network tab. Check for tracking pixels, analytics cookies, data layer objects (dataLayer, _gaq), and track what data is sent to analytics endpoints.'
  },
  'Are customer support widgets present?': {
    why: 'Support widgets (Intercom, Drift, Zendesk) can leak user data, have XSS vulnerabilities, allow social engineering, and may store conversation history insecurely. They often have elevated privileges for support agent features.',
    how: 'Look for chat widgets, help buttons, and embedded support interfaces. Check for support widget scripts (Intercom, Drift, LiveChat), test what user data is visible to support, and check if widgets load on authenticated pages exposing session data.'
  },
  'Are payment providers integrated?': {
    why: 'Payment integration must handle sensitive financial data securely. PCI DSS compliance is required. Look for card data handling, tokenization, and whether payment is on-site or redirects to processor. Payment flows often have unique logic vulnerabilities.',
    how: 'Check checkout flow, look for Stripe, PayPal, Square scripts/iframes, test if card details are entered on-site or external, check for payment tokens in requests, and verify no card data is logged/cached client-side.'
  },
  'Are external APIs called from the browser?': {
    why: 'Client-side API calls may expose API keys, leak data to third parties, have CORS misconfigurations, or allow attackers to monitor/intercept traffic. APIs called from client may have weaker authentication.',
    how: 'Monitor network tab for requests to external domains, check for third-party API endpoints, look for API keys in requests, test CORS policies, and identify all external services the app communicates with from the browser.'
  },
  'Are API keys present client-side?': {
    why: 'Client-side API keys can be extracted and abused. They may provide unauthorized access, exceed rate limits, or cost the organization money. Some keys grant excessive permissions. Keys should be server-side or use restricted scopes.',
    how: 'Search JavaScript for "api_key", "apikey", "token", "secret" strings. Check network requests for Authorization headers or key parameters. Look in localStorage, cookies, and environment configs. Extract keys from mobile apps.'
  },
  'Is a Content Security Policy present?': {
    why: `Content Security Policy is the single most effective defense against XSS (Cross-Site Scripting) attacks, which remain one of the most common and impactful vulnerability classes. Understanding the CSP tells you immediately whether XSS findings will be valid or blocked, saving hours of testing effort.

A missing CSP means the application has no browser-enforced defense against XSS. Every injected script will execute. Every data exfiltration attempt will succeed. This significantly increases the severity and exploitability of any XSS you discover. When reporting XSS without CSP, you can demonstrate full impact: cookie theft, keylogging, account takeover.

A permissive CSP with unsafe-inline or unsafe-eval is almost as bad as no CSP. These directives disable CSP's core protection by allowing inline JavaScript. Many developers implement CSP to check a compliance box, but include unsafe-inline because their code depends on inline scripts. As a tester, you can exploit this exactly like no CSP exists.

CSP bypass techniques are a valuable skill in bug bounty hunting. Even strict CSPs can be bypassed through allowed CDN domains, JSONP endpoints, or Angular template injection. When you understand the policy's allowed sources, you can search for vulnerabilities in those specific sources or techniques to abuse allowed domains.

CSP controls more than JavaScript execution. The frame-ancestors directive prevents clickjacking. The form-action directive restricts form submissions. The base-uri directive protects against base tag injection. Understanding the complete policy reveals multiple attack surfaces beyond just XSS.`,
    how: `Check the HTTP response headers first - this is where CSP is most commonly implemented. Use your browser's Developer Tools Network tab, click on the main document request, and look for a Content-Security-Policy header. If you see one, copy its entire value for analysis.

If there's no CSP header, check the HTML source for a meta tag: <meta http-equiv="Content-Security-Policy" content="...">. Some applications implement CSP via meta tag instead of headers. Both implementations work, though headers are preferred because they're harder for attackers to manipulate.

Use Google's CSP Evaluator (https://csp-evaluator.withgoogle.com/) to analyze the policy automatically. Paste the CSP and it will highlight weaknesses: unsafe-inline directives, overly permissive source lists, missing directives, and potential bypass techniques. This tool is essential for quickly assessing CSP strength.

Manually review the script-src directive, which controls JavaScript execution. Look for red flags: 'unsafe-inline' (allows inline scripts), 'unsafe-eval' (allows eval()), 'data:' (allows data URIs), '*' or https: (allows any HTTPS source), and CDN domains that might host JSONP endpoints. Each of these can potentially allow XSS.

Test the CSP's effectiveness practically. Try injecting a simple XSS payload like <script>alert(1)</script> or <img src=x onerror=alert(1)>. Check the browser console for CSP violation errors. If your payload is blocked, you'll see console errors explaining what the CSP blocked and why. This confirms the policy is active and enforced.

Examine other CSP directives beyond script-src. Check frame-ancestors (clickjacking protection), form-action (controls form submissions), base-uri (prevents base tag injection), and object-src (controls plugins like Flash). Missing directives mean those attack vectors aren't protected.

Research bypass techniques for the specific CSP you're facing. If the policy allows a CDN like https://cdnjs.cloudflare.com, search for known JSONP endpoints on that domain that could bypass CSP. If it allows https://ajax.googleapis.com, look for Angular library versions with template injection vulnerabilities. Bypassing CSP itself is often a valid security finding.

Document whether CSP is present, how strict it is, and any identified bypass possibilities. This becomes a critical factor in assessing XSS severity. XSS that bypasses a strict CSP is more valuable than XSS on a site with no CSP, because it demonstrates sophisticated exploitation. Include CSP analysis in all your XSS reports to show comprehensive testing.`
  },
  'Is the CSP strict or permissive?': {
    why: 'Permissive CSP (unsafe-inline, wildcard sources) provides little protection. Strict CSP with nonces/hashes and limited sources effectively prevents XSS. CSP bypasses may exist through allowed sources. CSP strictness indicates security maturity.',
    how: 'Analyze CSP directives: look for unsafe-inline, unsafe-eval, data:, * wildcards. Check if nonces/hashes are used. Test XSS payloads against CSP. Use tools like CSP Evaluator to assess policy strength.'
  },
  'Is CORS implemented?': {
    why: 'CORS controls cross-origin requests. Permissive CORS (Access-Control-Allow-Origin: *) with credentials allows data theft. Misconfigured CORS is a common vulnerability allowing unauthorized cross-origin access.',
    how: 'Check Access-Control-Allow-Origin header, test cross-origin requests from different domains, verify if credentials are allowed with wildcards, test with different Origin headers, and check preflight OPTIONS requests.'
  },
  'Is source code or documentation publicly available?': {
    why: 'Public source code enables white-box testing, reveals business logic, may contain secrets/credentials, shows security measures, and allows finding vulnerabilities through code review. Documentation reveals API details and internal workings.',
    how: 'Search GitHub for organization/app name, check for public repositories, look for exposed .git directories, search for API documentation, check package registries, and look for architecture diagrams or wikis.'
  }
};

export const ApplicationQuestionsModal = ({ 
  show, 
  handleClose, 
  activeTarget 
}) => {
  const [selectedQuestion, setSelectedQuestion] = useState(null);
  const [answers, setAnswers] = useState({});
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [editingAnswerId, setEditingAnswerId] = useState(null);
  const [newAnswerText, setNewAnswerText] = useState('');
  const [editAnswerText, setEditAnswerText] = useState('');
  const [error, setError] = useState(null);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [answerToDelete, setAnswerToDelete] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    if (show && activeTarget) {
      fetchAnswers();
    }
  }, [show, activeTarget]);

  useEffect(() => {
    if (selectedQuestion && answers[selectedQuestion]) {
      setNewAnswerText('');
    }
  }, [selectedQuestion, answers]);

  const fetchAnswers = async () => {
    if (!activeTarget) return;

    setLoading(true);
    setError(null);

    try {
      const response = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/application-questions/${activeTarget.id}/answers`
      );

      if (!response.ok) {
        throw new Error('Failed to fetch answers');
      }

      const data = await response.json();
      const answersMap = {};
      
      if (Array.isArray(data)) {
        data.forEach(answer => {
          if (!answersMap[answer.question]) {
            answersMap[answer.question] = [];
          }
          answersMap[answer.question].push(answer);
        });
      }

      setAnswers(answersMap);
    } catch (error) {
      console.error('Error fetching answers:', error);
      setError('Failed to load answers');
    } finally {
      setLoading(false);
    }
  };

  const handleSaveAnswer = async () => {
    if (!selectedQuestion || !newAnswerText.trim() || !activeTarget) return;

    setSaving(true);
    setError(null);

    try {
      const response = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/application-questions/${activeTarget.id}/answers`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            question: selectedQuestion,
            answer: newAnswerText.trim()
          })
        }
      );

      if (!response.ok) {
        throw new Error('Failed to save answer');
      }

      const savedAnswer = await response.json();
      
      setAnswers(prev => {
        const updated = { ...prev };
        if (!updated[selectedQuestion]) {
          updated[selectedQuestion] = [];
        }
        updated[selectedQuestion].push(savedAnswer);
        return updated;
      });

      setNewAnswerText('');
    } catch (error) {
      console.error('Error saving answer:', error);
      setError('Failed to save answer');
    } finally {
      setSaving(false);
    }
  };

  const handleUpdateAnswer = async (answerId) => {
    if (!editAnswerText.trim()) return;

    setSaving(true);
    setError(null);

    try {
      const response = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/application-questions/answers/${answerId}`,
        {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            answer: editAnswerText.trim()
          })
        }
      );

      if (!response.ok) {
        throw new Error('Failed to update answer');
      }

      const updatedAnswer = await response.json();
      
      setAnswers(prev => {
        const updated = { ...prev };
        if (updated[selectedQuestion]) {
          updated[selectedQuestion] = updated[selectedQuestion].map(a => 
            a.id === answerId ? updatedAnswer : a
          );
        }
        return updated;
      });

      setEditingAnswerId(null);
      setEditAnswerText('');
    } catch (error) {
      console.error('Error updating answer:', error);
      setError('Failed to update answer');
    } finally {
      setSaving(false);
    }
  };

  const handleDeleteClick = (answerId) => {
    setAnswerToDelete(answerId);
    setShowDeleteConfirm(true);
  };

  const handleConfirmDelete = async () => {
    if (!answerToDelete) return;

    setSaving(true);
    setError(null);
    setShowDeleteConfirm(false);

    try {
      const response = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/application-questions/answers/${answerToDelete}`,
        {
          method: 'DELETE'
        }
      );

      if (!response.ok) {
        throw new Error('Failed to delete answer');
      }

      setAnswers(prev => {
        const updated = { ...prev };
        if (updated[selectedQuestion]) {
          updated[selectedQuestion] = updated[selectedQuestion].filter(a => a.id !== answerToDelete);
        }
        return updated;
      });
    } catch (error) {
      console.error('Error deleting answer:', error);
      setError('Failed to delete answer');
    } finally {
      setSaving(false);
      setAnswerToDelete(null);
    }
  };

  const handleCancelDelete = () => {
    setShowDeleteConfirm(false);
    setAnswerToDelete(null);
  };

  const handleStartEdit = (answer) => {
    setEditingAnswerId(answer.id);
    setEditAnswerText(answer.answer);
  };

  const handleCancelEdit = () => {
    setEditingAnswerId(null);
    setEditAnswerText('');
  };

  const getQuestionCategory = (question) => {
    for (const category of QUESTIONS) {
      if (category.questions.includes(question)) {
        return category.category;
      }
    }
    return 'Unknown';
  };

  const allQuestions = QUESTIONS.flatMap(cat => cat.questions);

  return (
    <>
    <Modal 
      show={show} 
      onHide={handleClose} 
      fullscreen
      data-bs-theme="dark"
    >
      <Modal.Header closeButton className="bg-dark border-danger">
        <Modal.Title className="text-danger">
          Manual Recon
        </Modal.Title>
      </Modal.Header>
      <Modal.Body className="p-0">
        <div className="d-flex h-100" style={{ height: 'calc(100vh - 120px)' }}>
          <div 
            className="border-end border-danger" 
            style={{ 
              width: '400px', 
              minWidth: '400px',
              maxWidth: '400px',
              flexShrink: 0,
              overflowY: 'auto', 
              backgroundColor: '#1a1a1a' 
            }}
          >
            <div className="p-3 bg-dark border-bottom border-danger">
              <h6 className="text-danger mb-0">Questions by Category</h6>
            </div>
            <div className="p-3 border-bottom border-secondary">
              <Form.Control
                type="text"
                placeholder="Search questions..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                data-bs-theme="dark"
                size="sm"
              />
            </div>
            {QUESTIONS.map((category, catIndex) => {
              const filteredQuestions = category.questions.filter(q => 
                q.toLowerCase().includes(searchTerm.toLowerCase())
              );
              if (filteredQuestions.length === 0) return null;
              return (
              <div key={catIndex} className="border-bottom border-secondary">
                <div className="p-2 bg-dark">
                  <strong className="text-danger small">{category.category}</strong>
                </div>
                <ListGroup variant="flush">
                  {filteredQuestions.map((question, qIndex) => {
                    const hasAnswers = answers[question] && answers[question].length > 0;
                    const isSelected = selectedQuestion === question;
                    return (
                      <ListGroup.Item
                        key={qIndex}
                        action
                        active={isSelected}
                        onClick={() => setSelectedQuestion(question)}
                        className={`bg-dark text-white ${isSelected ? 'border-start border-3 border-danger' : ''}`}
                        style={{ 
                          cursor: 'pointer',
                          backgroundColor: isSelected ? '#2a1a1a !important' : undefined,
                          border: 'none',
                          borderBottom: '1px solid #333'
                        }}
                      >
                        <div className="d-flex justify-content-between align-items-start" style={{ gap: '8px' }}>
                          <span className="small" style={{ flex: '1 1 auto', minWidth: 0, wordWrap: 'break-word' }}>{question}</span>
                          {hasAnswers && (
                            <Badge bg="success" className="flex-shrink-0" style={{ minWidth: '24px', textAlign: 'center' }}>
                              {answers[question].length}
                            </Badge>
                          )}
                        </div>
                      </ListGroup.Item>
                    );
                  })}
                </ListGroup>
              </div>
              );
            })}
          </div>

          <div className="flex-fill p-4" style={{ overflowY: 'auto' }}>
            {loading ? (
              <div className="text-center py-5">
                <Spinner animation="border" variant="danger">
                  <span className="visually-hidden">Loading...</span>
                </Spinner>
              </div>
            ) : selectedQuestion ? (
              <>
                {error && (
                  <Alert variant="danger" dismissible onClose={() => setError(null)}>
                    {error}
                  </Alert>
                )}

                <div className="mb-4">
                  <h5 className="text-danger mb-2">{selectedQuestion}</h5>
                  <Badge bg="secondary" className="mb-3">
                    {getQuestionCategory(selectedQuestion)}
                  </Badge>
                </div>

                {QUESTION_GUIDANCE[selectedQuestion] && (
                  <div className="mb-4">
                    <Accordion data-bs-theme="dark">
                      <Accordion.Item eventKey="0" className="bg-dark border-danger">
                        <Accordion.Header>
                          <strong className="text-danger">Help Me Learn!</strong>
                        </Accordion.Header>
                        <Accordion.Body className="bg-dark text-white">
                          <div className="mb-4">
                            <h6 className="text-danger mb-3">
                              Why is this important?
                            </h6>
                            <div style={{ lineHeight: '1.8' }}>
                              {QUESTION_GUIDANCE[selectedQuestion].why.split('\n\n').map((paragraph, idx) => (
                                <p key={idx} className="mb-3">
                                  {paragraph}
                                </p>
                              ))}
                            </div>
                          </div>
                          <div>
                            <h6 className="text-danger mb-3">
                              How do I find this information?
                            </h6>
                            <div style={{ lineHeight: '1.8' }}>
                              {QUESTION_GUIDANCE[selectedQuestion].how.split('\n\n').map((paragraph, idx) => (
                                <p key={idx} className="mb-3">
                                  {paragraph}
                                </p>
                              ))}
                            </div>
                          </div>
                        </Accordion.Body>
                      </Accordion.Item>
                    </Accordion>
                  </div>
                )}

                <div className="mb-4">
                  <h6 className="text-white mb-3">Your Answers</h6>
                  {answers[selectedQuestion] && answers[selectedQuestion].length > 0 ? (
                    <div className="space-y-3">
                      {answers[selectedQuestion].map((answer) => (
                        <div key={answer.id} className="border border-secondary rounded p-3 mb-3 bg-dark">
                          {editingAnswerId === answer.id ? (
                            <div>
                              <Form.Control
                                as="textarea"
                                rows={3}
                                value={editAnswerText}
                                onChange={(e) => setEditAnswerText(e.target.value)}
                                className="mb-2"
                                data-bs-theme="dark"
                              />
                              <div className="d-flex gap-2">
                                <Button
                                  variant="success"
                                  size="sm"
                                  onClick={() => handleUpdateAnswer(answer.id)}
                                  disabled={saving || !editAnswerText.trim()}
                                >
                                  {saving ? <Spinner animation="border" size="sm" /> : 'Save'}
                                </Button>
                                <Button
                                  variant="secondary"
                                  size="sm"
                                  onClick={handleCancelEdit}
                                  disabled={saving}
                                >
                                  Cancel
                                </Button>
                              </div>
                            </div>
                          ) : (
                            <div>
                              <p className="text-white mb-2">{answer.answer}</p>
                              <div className="d-flex gap-2">
                                <Button
                                  variant="outline-warning"
                                  size="sm"
                                  onClick={() => handleStartEdit(answer)}
                                >
                                  Edit
                                </Button>
                                <Button
                                  variant="outline-danger"
                                  size="sm"
                                  onClick={() => handleDeleteClick(answer.id)}
                                >
                                  Delete
                                </Button>
                              </div>
                              {answer.created_at && (
                                <small className="text-white-50 d-block mt-2">
                                  {new Date(answer.created_at).toLocaleString()}
                                </small>
                              )}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-white-50">No answers yet. Add your first answer below.</p>
                  )}
                </div>

                <div className="border-top border-secondary pt-4">
                  <h6 className="text-white mb-3">Add New Answer</h6>
                  <Form.Control
                    as="textarea"
                    rows={4}
                    value={newAnswerText}
                    onChange={(e) => setNewAnswerText(e.target.value)}
                    placeholder="Enter your answer here..."
                    className="mb-3"
                    data-bs-theme="dark"
                  />
                  <Button
                    variant="danger"
                    onClick={handleSaveAnswer}
                    disabled={saving || !newAnswerText.trim()}
                  >
                    {saving ? (
                      <>
                        <Spinner animation="border" size="sm" className="me-2" />
                        Saving...
                      </>
                    ) : (
                      'Save Answer'
                    )}
                  </Button>
                </div>
              </>
            ) : (
              <div className="py-4 px-4">
                <Card className="bg-dark border-danger">
                  <Card.Body>
                    <h4 className="text-danger mb-4">High-Level Questions</h4>
                    
                    <div className="text-white mb-4">
                      <h5 className="text-danger mb-3">Foundation for Threat Modeling</h5>
                      <p>
                        High-level questions help you deeply understand the target application's architecture, authentication, 
                        authorization, data handling, and business logic. This foundational knowledge is essential for effective 
                        STRIDE threat modeling, as you cannot identify threats without first understanding how the system works.
                      </p>
                    </div>

                    <div className="text-white mb-4">
                      <h5 className="text-danger mb-3">How This Supports Threat Modeling</h5>
                      <p className="mb-2">
                        By systematically answering these questions, you'll identify:
                      </p>
                      <ul className="mb-2">
                        <li><strong>Spoofing opportunities</strong> - Authentication mechanisms and identity verification points</li>
                        <li><strong>Tampering targets</strong> - Data flows, storage locations, and integrity controls</li>
                        <li><strong>Repudiation risks</strong> - Logging mechanisms, audit trails, and accountability systems</li>
                        <li><strong>Information disclosure vectors</strong> - Sensitive data locations, access controls, and data exposure points</li>
                        <li><strong>Denial of service weaknesses</strong> - Resource-intensive operations, rate limiting, and availability controls</li>
                        <li><strong>Elevation of privilege paths</strong> - Authorization boundaries, privilege levels, and trust boundaries</li>
                      </ul>
                    </div>

                    <div className="text-white mb-4">
                      <h5 className="text-danger mb-3">How to use this effectively</h5>
                      <ol className="mb-2">
                        <li className="mb-2">
                          <strong>Start early:</strong> Begin answering questions during initial reconnaissance before diving into 
                          vulnerability testing. Your answers will guide your testing strategy.
                        </li>
                        <li className="mb-2">
                          <strong>Be thorough:</strong> Each question comes with educational content explaining why it matters 
                          and how to find the answer. Click any question to see the "Help Me Learn!" section.
                        </li>
                        <li className="mb-2">
                          <strong>Update continuously:</strong> As you discover new information during testing, come back and 
                          add it. You can have multiple answers per question as your understanding evolves.
                        </li>
                        <li className="mb-2">
                          <strong>Use it as a checklist:</strong> Questions marked with a green badge have been answered. 
                          Aim to answer questions across all 8 categories for complete coverage.
                        </li>
                        <li className="mb-2">
                          <strong>Reference during testing:</strong> When you find something interesting during vulnerability 
                          testing, check your answers here to understand the broader context and implications.
                        </li>
                      </ol>
                    </div>

                    <div className="text-white mb-3">
                      <h5 className="text-danger mb-3">The 8 Categories</h5>
                      <p className="mb-2">Questions are organized into these categories:</p>
                      <div className="row g-2">
                        <div className="col-md-6">
                          <Badge bg="secondary" className="w-100 text-start p-2">Application Identity & Scope</Badge>
                        </div>
                        <div className="col-md-6">
                          <Badge bg="secondary" className="w-100 text-start p-2">Technology Stack & Frameworks</Badge>
                        </div>
                        <div className="col-md-6">
                          <Badge bg="secondary" className="w-100 text-start p-2">Hosting, Infrastructure & Delivery</Badge>
                        </div>
                        <div className="col-md-6">
                          <Badge bg="secondary" className="w-100 text-start p-2">Network & Transport Security</Badge>
                        </div>
                        <div className="col-md-6">
                          <Badge bg="secondary" className="w-100 text-start p-2">Traffic Controls & Abuse Protection</Badge>
                        </div>
                        <div className="col-md-6">
                          <Badge bg="secondary" className="w-100 text-start p-2">Authentication & Identity Model</Badge>
                        </div>
                        <div className="col-md-6">
                          <Badge bg="secondary" className="w-100 text-start p-2">Authorization, Roles & Data Model</Badge>
                        </div>
                        <div className="col-md-6">
                          <Badge bg="secondary" className="w-100 text-start p-2">Client-Side, Integrations & Policies</Badge>
                        </div>
                      </div>
                    </div>

                    <Alert variant="info" className="mb-0 mt-4">
                      <strong>Get started:</strong> Select any question from the left sidebar to begin. Each question includes 
                      contextual help explaining its importance in security testing and practical guidance on finding the answer.
                    </Alert>
                  </Card.Body>
                </Card>
              </div>
            )}
          </div>
        </div>
      </Modal.Body>
      <Modal.Footer className="bg-dark border-danger">
        <Button variant="outline-danger" onClick={handleClose}>
          Close
        </Button>
      </Modal.Footer>
    </Modal>

    <Modal 
      show={showDeleteConfirm} 
      onHide={handleCancelDelete}
      centered
      data-bs-theme="dark"
    >
      <Modal.Header closeButton className="bg-dark border-danger">
        <Modal.Title className="text-danger">Confirm Delete</Modal.Title>
      </Modal.Header>
      <Modal.Body className="bg-dark text-white">
        Are you sure you want to delete this answer? This action cannot be undone.
      </Modal.Body>
      <Modal.Footer className="bg-dark border-danger">
        <Button variant="outline-secondary" onClick={handleCancelDelete}>
          Cancel
        </Button>
        <Button variant="danger" onClick={handleConfirmDelete} disabled={saving}>
          {saving ? (
            <>
              <Spinner animation="border" size="sm" className="me-2" />
              Deleting...
            </>
          ) : (
            'Delete'
          )}
        </Button>
      </Modal.Footer>
    </Modal>
  </>
  );
};

