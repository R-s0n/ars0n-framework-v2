# Web Application Security Testing Checklist

## Information Gathering
- [ ] Identify web server, technologies, and frameworks
- [ ] Review robots.txt, sitemap.xml, crossdomain.xml, clientaccesspolicy.xml
- [ ] Check for .git, .svn, .env exposure
- [ ] Enumerate subdomains
- [ ] Map application architecture and entry points
- [ ] Identify all user input vectors (forms, APIs, WebSockets, file uploads)

## Configuration & Deployment
- [ ] Check for default credentials on admin interfaces
- [ ] Test for HTTP methods enabled (PUT, DELETE, TRACE, OPTIONS)
- [ ] Check HTTP security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options)
- [ ] Verify TLS/SSL configuration (SSL Labs)
- [ ] Check for verbose error messages / stack traces
- [ ] Test for directory listing enabled
- [ ] Check for server-status / server-info pages
- [ ] Look for exposed admin panels (/admin, /wp-admin, /manager)
- [ ] Test for CORS misconfiguration

## Authentication
- [ ] Test for username enumeration (registration, login, password reset)
- [ ] Test password policy (minimum length, complexity)
- [ ] Test account lockout mechanism
- [ ] Test for brute-force resistance
- [ ] Test "remember me" functionality security
- [ ] Test password reset mechanism (token predictability, reuse, expiration)
- [ ] Test multi-factor authentication bypass
- [ ] Test for session fixation
- [ ] Test for credential stuffing protection
- [ ] Test OAuth/OIDC implementation
- [ ] Test JWT implementation (algorithm confusion, none algorithm, weak key)
- [ ] Test for authentication bypass via direct request

## Session Management
- [ ] Check session token randomness and entropy
- [ ] Test session timeout and invalidation
- [ ] Test for session fixation
- [ ] Check cookie attributes (Secure, HttpOnly, SameSite, Path, Domain)
- [ ] Test for concurrent session handling
- [ ] Test session invalidation on logout
- [ ] Test session invalidation on password change
- [ ] Check for session token in URL
- [ ] Test for CSRF protection on all state-changing requests

## Authorization
- [ ] Test for horizontal privilege escalation (user A accessing user B's data)
- [ ] Test for vertical privilege escalation (user → admin)
- [ ] Test for IDOR on all resource identifiers
- [ ] Test for forced browsing to privileged pages
- [ ] Test for missing function-level access control
- [ ] Test for insecure direct object references in file operations
- [ ] Verify authorization on all API endpoints
- [ ] Test for path traversal in authorization context

## Input Validation
- [ ] Test for reflected XSS on all input points
- [ ] Test for stored XSS on all persistent input
- [ ] Test for DOM-based XSS in JavaScript
- [ ] Test for SQL injection (error-based, blind, time-based)
- [ ] Test for command injection / OS injection
- [ ] Test for LDAP injection
- [ ] Test for XML injection / XXE
- [ ] Test for XPath injection
- [ ] Test for SSTI (Server-Side Template Injection)
- [ ] Test for SSRF (Server-Side Request Forgery)
- [ ] Test for NoSQL injection
- [ ] Test for CRLF injection
- [ ] Test for header injection (Host header, email headers)
- [ ] Test for file path traversal / LFI / RFI
- [ ] Test for HTTP parameter pollution
- [ ] Test for mass assignment / autobinding

## File Upload
- [ ] Test for unrestricted file upload (webshell)
- [ ] Test content-type validation bypass
- [ ] Test file extension validation bypass (double extension, null byte)
- [ ] Test for file size limits
- [ ] Test for path traversal in filename
- [ ] Test for XXE via SVG, DOCX, XLSX upload
- [ ] Test for image processing vulnerabilities (ImageMagick)
- [ ] Test for polyglot file upload
- [ ] Check if uploaded files are served with proper Content-Type
- [ ] Check if uploaded files are in web-accessible directory

## Business Logic
- [ ] Test for price manipulation
- [ ] Test for quantity manipulation (negative, zero, excessive)
- [ ] Test for race conditions on critical operations
- [ ] Test for workflow bypass (skipping steps)
- [ ] Test for time-based manipulation
- [ ] Test for coupon/discount abuse
- [ ] Test for referral system abuse
- [ ] Test for feature abuse that leads to data exposure
- [ ] Test for integer overflow/underflow in calculations

## Client-Side
- [ ] Test for clickjacking on sensitive pages
- [ ] Test for open redirects
- [ ] Test for client-side validation bypass
- [ ] Test for sensitive data in client-side storage (localStorage, sessionStorage)
- [ ] Test for sensitive data in browser history
- [ ] Test for WebSocket security issues
- [ ] Test for postMessage vulnerabilities
- [ ] Test for DOM clobbering
- [ ] Test for prototype pollution
- [ ] Review JavaScript for hardcoded secrets

## API Security
- [ ] Test for BOLA (Broken Object-Level Authorization)
- [ ] Test for broken authentication on API endpoints
- [ ] Test for excessive data exposure in API responses
- [ ] Test for mass assignment via API
- [ ] Test for missing rate limiting on API
- [ ] Test for broken function-level authorization
- [ ] Test for SSRF through API parameters
- [ ] Test for improper API versioning
- [ ] Test GraphQL introspection and batch queries
- [ ] Review API documentation for hidden/debug endpoints

## Cryptography
- [ ] Check for weak cipher suites
- [ ] Test for padding oracle attacks
- [ ] Check for sensitive data transmitted in plaintext
- [ ] Verify proper use of HSTS
- [ ] Check for mixed content (HTTP/HTTPS)
- [ ] Test for weak random number generation
- [ ] Check certificate pinning (mobile apps)

## Error Handling & Logging
- [ ] Test for verbose error messages
- [ ] Check for stack traces in responses
- [ ] Test for information disclosure in error pages
- [ ] Verify custom error pages don't leak info
- [ ] Test for log injection

## Cloud & Infrastructure
- [ ] Test for subdomain takeover
- [ ] Check for exposed S3 buckets / Azure blobs
- [ ] Test for cloud metadata SSRF
- [ ] Check for exposed Docker/Kubernetes dashboards
- [ ] Test for DNS zone transfer
- [ ] Check for exposed .git/.svn repositories
