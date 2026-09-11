# Reconnaissance Methodology for Bug Bounty

## Subdomain Enumeration

### Passive Enumeration
```bash
# Certificate Transparency
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u

# Subfinder
subfinder -d target.com -all -recursive

# Amass (passive)
amass enum -passive -d target.com

# Assetfinder
assetfinder --subs-only target.com

# GitHub Subdomains
github-subdomains -d target.com -t GITHUB_TOKEN

# Chaos (ProjectDiscovery)
chaos -d target.com
```

### Active Enumeration
```bash
# DNS Brute-forcing
puredns bruteforce wordlist.txt target.com

# Amass (active)
amass enum -active -d target.com -brute

# Alterations/Permutations
altdns -i subdomains.txt -o permutations.txt -w words.txt
dnsgen subdomains.txt | massdns -r resolvers.txt -t A -o S

# Virtual Host Discovery
ffuf -w vhosts.txt -u http://TARGET_IP -H "Host: FUZZ.target.com" -fs DEFAULT_SIZE
```

### Subdomain Validation
```bash
# Resolve subdomains
massdns -r resolvers.txt -t A -o S subdomains.txt > resolved.txt

# HTTP probing
httpx -l subdomains.txt -title -status-code -tech-detect -o live_hosts.txt

# Screenshot
gowitness file -f live_hosts.txt
eyewitness --web -f live_hosts.txt
```

## Content Discovery

### Directory & File Brute-forcing
```bash
# ffuf (fast)
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403

# Feroxbuster (recursive)
feroxbuster -u https://target.com -w wordlist.txt --depth 3

# With extensions
ffuf -u https://target.com/FUZZ -w wordlist.txt -e .php,.asp,.aspx,.jsp,.bak,.old,.txt,.conf,.env,.json,.xml,.yml,.yaml,.sql,.log,.git
```

### Backup & Hidden Files
```
# Common backup patterns:
/index.php.bak
/config.php.old
/database.sql
/.env
/.git/config
/.svn/entries
/wp-config.php.bak
/web.config.bak
/backup.zip
/backup.tar.gz
/site.sql
/.DS_Store
/Thumbs.db
/error_log
/debug.log
```

### JavaScript Analysis
```bash
# Extract URLs from JavaScript
cat urls.txt | getJS --complete | tee js_files.txt
cat js_files.txt | xargs -I{} python3 linkfinder.py -i {} -o cli

# Find secrets in JS
nuclei -l js_files.txt -t exposures/tokens/
trufflehog filesystem --directory ./js_dumps/

# Extract API endpoints
cat js_files.txt | xargs -I{} curl -s {} | grep -oP '["'"'"'](/api/[^"'"'"'\s]+)["'"'"']' | sort -u
```

### Wayback Machine
```bash
# Historical URLs
waybackurls target.com | sort -u > wayback_urls.txt

# Filter for interesting files
cat wayback_urls.txt | grep -E '\.(php|asp|aspx|jsp|json|xml|conf|env|sql|bak|old|log|txt)$'

# Filter for parameters
cat wayback_urls.txt | grep '=' | qsreplace 'FUZZ' | sort -u
```

## Google Dorking

### Common Dorks for Bug Bounty
```
# Find sensitive files
site:target.com filetype:pdf | filetype:doc | filetype:xls
site:target.com filetype:xml | filetype:json | filetype:yaml
site:target.com filetype:sql | filetype:log | filetype:bak
site:target.com filetype:env | filetype:conf | filetype:cfg

# Find exposed pages
site:target.com inurl:admin | inurl:login | inurl:dashboard
site:target.com inurl:api | inurl:graphql | inurl:swagger
site:target.com inurl:debug | inurl:test | inurl:staging
site:target.com intitle:"index of" | intitle:"directory listing"

# Find sensitive information
site:target.com intext:"password" | intext:"api_key" | intext:"secret"
site:target.com ext:env | ext:yml "password"
"target.com" inurl:pastebin.com | inurl:trello.com | inurl:jira

# Find subdomains
site:*.target.com -www
```

### GitHub Dorking
```
# Search for secrets
"target.com" password
"target.com" api_key
"target.com" secret_key
"target.com" AWS_ACCESS_KEY
"target.com" PRIVATE_KEY
org:targetorg password
org:targetorg secret
org:targetorg api_key
org:targetorg token
```

## Port Scanning & Service Discovery

```bash
# Quick scan
nmap -sV -sC -T4 target.com

# Full port scan
nmap -p- -T4 target.com

# Service version detection
nmap -sV -p 80,443,8080,8443,8000,3000,5000,9090 target.com

# Masscan for fast full port scan
masscan -p0-65535 TARGET_IP --rate 10000

# Shodan CLI
shodan search "hostname:target.com"
shodan host TARGET_IP
```

## Technology Stack Identification

### Tools & Techniques
```bash
# Wappalyzer CLI
wappalyzer https://target.com

# WhatWeb
whatweb https://target.com

# Check headers
curl -sI https://target.com | grep -i "x-powered-by\|server\|x-aspnet\|x-generator"

# Identify CMS
# WordPress: /wp-admin, /wp-content, /wp-includes
# Drupal: /misc/drupal.js, /CHANGELOG.txt
# Joomla: /administrator, /components, /modules

# Check for known frameworks
# React: Look for react in JS bundles
# Angular: ng-app, angular.js
# Vue: __vue__, Vue.js
# Next.js: /_next/
# Rails: X-Powered-By: Phusion Passenger, csrf-token meta tag
# Django: csrfmiddlewaretoken, djdt (debug toolbar)
# Laravel: laravel_session cookie, XSRF-TOKEN
# Spring: JSESSIONID, /error page format
```

## Attack Surface Mapping

### Prioritization
1. **High Priority**: Login pages, API endpoints, file upload, payment, admin panels
2. **Medium Priority**: User profiles, search functionality, contact forms, settings
3. **Low Priority**: Static pages, marketing pages, public content

### Parameter Analysis
```bash
# Collect all parameters
cat urls.txt | grep '?' | unfurl keys | sort | uniq -c | sort -rn

# Find reflection points
cat urls.txt | kxss

# Test for injection points
cat params.txt | qsreplace '<test>' | httpx -match-string '<test>'
```

## Automation Pipeline

### Recommended Flow
```
1. Subdomain Enumeration (passive + active)
   ↓
2. DNS Resolution + HTTP Probing
   ↓
3. Port Scanning + Service Detection
   ↓
4. Technology Fingerprinting
   ↓
5. Content Discovery (directories, files, JS)
   ↓
6. Parameter Discovery
   ↓
7. Vulnerability Scanning (nuclei)
   ↓
8. Manual Testing (targeted)
```

### Nuclei Templates
```bash
# Run all templates
nuclei -l live_hosts.txt -t nuclei-templates/ -severity critical,high,medium

# Specific categories
nuclei -l urls.txt -t cves/
nuclei -l urls.txt -t vulnerabilities/
nuclei -l urls.txt -t exposures/
nuclei -l urls.txt -t misconfiguration/
nuclei -l urls.txt -t takeovers/
```
