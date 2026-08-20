# Ars0n Framework - Manual Crawling Extension

A Chrome browser extension that captures HTTP traffic during manual application exploration, seamlessly integrating with the Ars0n Framework v2 for comprehensive endpoint discovery and attack surface mapping.

## Overview

The Manual Crawling Extension bridges the gap between automated reconnaissance and manual testing by capturing every HTTP request you make while browsing a target application. This approach discovers authenticated endpoints, dynamic content, and complex user flows that automated crawlers often miss.

## Features

- **Real-Time Request Capture**: Automatically captures all HTTP/HTTPS requests as you browse
- **Endpoint Discovery**: Intelligently identifies and deduplicates API endpoints and URL patterns
- **Parameter Tracking**: Records query parameters and POST body data for each endpoint
- **Authentication Awareness**: Detects and tracks authentication headers, cookies, and session tokens
- **Smart Filtering**: Automatically filters out static assets (CSS, JS, images) while focusing on functional endpoints
- **Live Statistics**: Shows real-time count of captured requests and discovered endpoints
- **Scope Control**: Only captures requests matching your target domain
- **Framework Integration**: Seamlessly sends captured data to your local Ars0n Framework instance

## Installation

### Prerequisites

- Chrome browser (version 88 or higher)
- Ars0n Framework v2 running locally at `http://localhost`

### Development Installation (Unpacked Extension)

1. Download the extension files to your local machine

2. Open Chrome and navigate to `chrome://extensions/`

3. Enable "Developer mode" using the toggle in the top-right corner

4. Click "Load unpacked"

5. Select the `extension` folder from your Ars0n Framework directory

6. The Ars0n Framework icon should appear in your Chrome toolbar

7. Pin the extension for easy access (click the puzzle piece icon → pin)

## Usage

### Initial Setup

1. Start the Ars0n Framework v2 on your machine

2. Create a URL-type scope target in the framework

3. Navigate to the Manual Crawling section for that target

4. Click "Start Manual Crawl" in the framework

### Capturing Traffic

1. Click the Ars0n Framework extension icon in Chrome

2. Click "Start Capture"

3. Browse to your target URL and interact with the application normally:
   - Log in with valid credentials
   - Click through different pages and features
   - Submit forms
   - Trigger AJAX requests
   - Explore authenticated areas
   - Test different user roles/permissions

4. Watch the live counter showing captured requests

5. When finished exploring, click "Stop Capture"

6. Return to the Ars0n Framework to view all discovered endpoints

### Viewing Results

All captured endpoints are automatically stored in your Ars0n Framework database and can be viewed in the Manual Crawling Results section, including:

- Full endpoint URLs and paths
- HTTP methods used
- Query parameters discovered
- Request/response headers
- Status codes
- Timestamps
- Organized by endpoint patterns (e.g., `/api/users/{id}`)

## Configuration

### Target URL

The extension automatically detects the active target from your Ars0n Framework. You can also manually set the target URL in the extension popup if needed.

### Scope Settings

- **Include Subdomains**: Capture requests to all subdomains of the target
- **Capture Static Assets**: Include CSS, JavaScript, images, and other static files
- **Capture External Requests**: Include requests to third-party domains (CDNs, APIs)

### Framework Connection

By default, the extension connects to `http://localhost` (the nginx reverse proxy automatically routes to the backend API). 

**To configure a different URL:**
1. Click the extension icon
2. Click "Connection Settings"
3. Enter your framework URL (e.g., `http://192.168.1.100:8000` or `https://your-server.com:8000`)
4. Click "Save Settings"
5. The extension will test the connection automatically

**Supported URL formats:**
- `http://localhost` (default - nginx handles routing)
- `http://192.168.1.100` (local network)
- `https://remote-server.com` (remote server)
- Custom port: `http://localhost:8080` (if running on non-standard port)

## Technical Architecture

Capture comes from three sources that feed one queue. Records describing the same request are
merged rather than stored twice.

| Source | Always on | Gives you | Does not give you |
| --- | --- | --- | --- |
| `chrome.webRequest` | yes | Every request the browser makes, real headers including `Cookie` and `Set-Cookie`, status codes, redirect chains, aborted requests | Any body |
| Page hook (`injected.js`) | yes | The page's own `fetch`, `XMLHttpRequest`, and `sendBeacon`, with request **and response** bodies | Navigations, subresources, worker traffic |
| Deep capture (`chrome.debugger`) | **opt-in** | Everything above with full bodies, including navigations, form posts, subresources, and WebSocket handshakes | Nothing, but it has real costs (below) |

### Why three

`webRequest` sees the network but never a body, so an application whose entire API surface is
`fetch` calls looked nearly empty: paths were recorded, payloads and responses were not. The page
hook runs inside the page's own JavaScript context and wraps `fetch`/`XHR`, which is exactly where
that traffic lives. Deep capture closes the last gap for everything JavaScript did not initiate.

### Deep capture trade-offs

Enable it with the **Deep Capture** switch in the popup. It can be turned on and off mid-session.

- Chrome shows the "being controlled by automated software" banner while attached
- Only one debugger client per tab, so it cannot attach to a tab that has DevTools open. That tab
  is reported in the popup and skipped; the rest of the session continues normally
- The `debugger` permission is requested at install time even when the feature is off

### Scope

Capture is filtered by **host**, never by tab. Requests issued by a page's own service worker
arrive with no tab id, and OAuth popups and `target="_blank"` flows arrive on a different tab;
filtering by tab discarded all of them.

The popup shows the resolved in-scope host list while recording, and separately lists hosts it saw
and **rejected**, with a hit count and an Add button. If the app's API lives on a different
registrable domain, that is where it shows up, and one click brings it into scope without
restarting the recording.

### Reliability

- Session state and the upload queue live in `chrome.storage.session`, so the browser terminating
  the MV3 service worker does not end the recording
- A `chrome.alarms` tick plus a long-lived content-script port keep the worker alive
- Captures are queued and uploaded in batches with retry, so a slow or restarting framework costs
  latency, not data
- A heartbeat every 20 seconds tells the framework the session is genuinely alive, so a dead
  extension is reported as stalled rather than silently pretending to record

### Data Captured

For each HTTP request:
- Full URL and a templated endpoint (`/api/users/{id}`, `/graphql#GetUser`)
- HTTP method (GET, POST, PUT, PATCH, DELETE, ...)
- Request headers including `Cookie`, and response headers including `Set-Cookie`
- Query parameters, request body (JSON, form-urlencoded, and multipart field names), response body
- GraphQL operation name, resource type, and initiator
- Redirect chain, error text for aborted or failed requests, and duration
- Which sources contributed, so a metadata-only record is distinguishable from one with bodies

Bodies are capped (512 KB by default) and truncation is recorded rather than hidden. Binary
responses are described, not stored.

### Endpoint Pattern Recognition

- `/api/users/123` and `/api/users/456` become `/api/users/{id}`
- UUIDs and Mongo ObjectIds are templated the same way
- `/products?id=1` and `/products?id=2` become `/products?id={value}`
- GraphQL is split by operation, so `POST /graphql` becomes `/graphql#GetUser`,
  `/graphql#DeleteAccount`, and so on, instead of collapsing an entire API into one row

## Privacy & Security

### Data Handling

- **Local Processing**: All data is sent directly to your local Ars0n Framework instance
- **No External Services**: No data is sent to third-party servers or cloud services
- **User Control**: You control when capture starts and stops
- **Sensitive Data Warning**: Captures include session cookies, authorization headers, and full
  response bodies in plain text. Treat the framework database as credential material.

### Best Practices

- Only use on targets you own or have explicit permission to test
- Be cautious when capturing traffic on production systems
- Review captured data for sensitive information before sharing exports
- Clear capture history when testing different targets
- Use secure connections (HTTPS) when accessing the framework remotely

## Troubleshooting

### Nothing is being captured

- Open the popup while recording. The **Scope** card shows exactly what is in scope, and below it,
  hosts that were seen and rejected. If the app's API host is in the second list, click Add.
- Check **Pending Upload**. If it keeps climbing, the framework is unreachable; the captures are
  safe in the queue and will upload when it returns.
- Check the **Status** badge. If it reads Idle, the session ended. The popup reads state from the
  service worker, so this reflects reality rather than a stale flag.

### API calls are recorded but bodies are empty

- **With Response Body** in the popup counts how many captures carry one. If it stays at zero while
  requests climb, the page hook is not seeing the traffic.
- The page hook only covers `fetch`, `XHR`, and `sendBeacon`. Navigations, form posts, and
  subresource loads need **Deep Capture**.
- Confirm **Capture Response Bodies** is on.
- Binary responses are never stored, only described.

### Deep capture will not attach to a tab

Chrome allows one debugger client per tab. Close DevTools on that tab and toggle Deep Capture off
and on. The popup names each tab it could not attach to.

### The framework says "No Active Recording" while the popup says Capturing

This should not happen. The framework decides using the extension's heartbeat, so if the service
worker dies the session is reported as stalled within 90 seconds and cleanup marks it abandoned. If
you see a disagreement, check the browser console for `[MANUAL-CRAWL]` errors.

### Connection to Framework Failed

- Verify the backend is running: `docker-compose ps`
- Confirm the Framework URL in Connection Settings (default `http://localhost`)
- Check the browser console for error messages

### Still missing

- WebSocket **messages** are not captured (the handshake is, under deep capture)
- Requests made before the page hook receives its configuration at document start may be recorded
  by `webRequest` without a body

## Testing

The pure capture logic (scope matching, endpoint naming, GraphQL operation extraction, body
parsing, source merging) has unit tests that run without a browser:

```bash
cd extension
node lib/scope.test.mjs           # scope, endpoint naming, GraphQL, body parsing, source merging
node lib/captureStages.test.mjs   # the webRequest stage machine, replayed in chrome's event order
node injected.test.mjs            # the page hook, driven against a simulated page
node popup.test.mjs               # the scope list: row order, DOM identity, striping
```

`node --test extension/` does NOT recurse into `lib/`, so run the four files by path.

`injected.test.mjs` runs the real `injected.js` inside a sandboxed fake page and asserts both that
it captures bodies and that it does not change what the page observes from `fetch`, `XHR`,
`sendBeacon`, and form submission.

`captureStages.test.mjs` replays the eight events chrome fires for a request that redirects, all
carrying one `requestId`. That sequence is the point: each stage looks correct on its own, and the
record was still destroyed by the order, because the redirect destination is a different HTTP
message writing over the request that caused it.

`popup.test.mjs` runs the real `popup.js` against a minimal DOM and asserts that out-of-scope rows
never reorder as their hit counts change and that their DOM nodes are reused rather than recreated.
Both matter: the list refreshes every two seconds while traffic is flowing, and each row carries an
Add button the user is trying to click.

## Development Installation (Unpacked Extension)

1. Download the extension files to your local machine

2. Open Chrome and navigate to `chrome://extensions/`

3. Enable "Developer mode" using the toggle in the top-right corner

4. Click "Load unpacked"

5. Select the `extension` folder from your Ars0n Framework directory

6. The Ars0n Framework icon should appear in your Chrome toolbar

7. Pin the extension for easy access (click the puzzle piece icon → pin)

## Usage

### Initial Setup

1. Start the Ars0n Framework v2 on your machine

2. Create a URL-type scope target in the framework

3. Navigate to the Manual Crawling section for that target

4. Click "Start Manual Crawl" in the framework

### Capturing Traffic

1. Click the Ars0n Framework extension icon in Chrome

2. Click "Start Capture"

3. Browse to your target URL and interact with the application normally:
   - Log in with valid credentials
   - Click through different pages and features
   - Submit forms
   - Trigger AJAX requests
   - Explore authenticated areas
   - Test different user roles/permissions

4. Watch the live counter showing captured requests

5. When finished exploring, click "Stop Capture"

6. Return to the Ars0n Framework to view all discovered endpoints

### Viewing Results

All captured endpoints are automatically stored in your Ars0n Framework database and can be viewed in the Manual Crawling Results section, including:

- Full endpoint URLs and paths
- HTTP methods used
- Query parameters discovered
- Request/response headers
- Status codes
- Timestamps
- Organized by endpoint patterns (e.g., `/api/users/{id}`)

## Configuration

### Target URL

The extension automatically detects the active target from your Ars0n Framework. You can also manually set the target URL in the extension popup if needed.

### Scope Settings

- **Include Subdomains**: Capture requests to all subdomains of the target
- **Capture Static Assets**: Include CSS, JavaScript, images, and other static files
- **Capture External Requests**: Include requests to third-party domains (CDNs, APIs)

### Framework Connection

By default, the extension connects to `http://localhost` (the nginx reverse proxy automatically routes to the backend API). 

**To configure a different URL:**
1. Click the extension icon
2. Click "Connection Settings"
3. Enter your framework URL (e.g., `http://192.168.1.100:8000` or `https://your-server.com:8000`)
4. Click "Save Settings"
5. The extension will test the connection automatically

**Supported URL formats:**
- `http://localhost` (default - nginx handles routing)
- `http://192.168.1.100` (local network)
- `https://remote-server.com` (remote server)
- Custom port: `http://localhost:8080` (if running on non-standard port)

## Technical Architecture

### Chrome APIs Used

- **chrome.webRequest**: Observes every request the browser makes, including requests issued by the
  page's own service worker. Used with the `extraHeaders` option so `Cookie` and `Set-Cookie` are
  visible.
- **chrome.storage.session**: Holds the capture session and the pending upload queue. This is what
  lets recording survive the browser terminating the MV3 service worker.
- **chrome.alarms** and a long-lived content-script port: keep the service worker alive during a
  session and wake it back up if it is terminated anyway.
- **chrome.tabs / chrome.runtime**: messaging between the worker, the popup, and the page indicator.

Note: this extension no longer uses `chrome.debugger`. That approach could read response bodies, but
it showed the "Chrome is being controlled by automated software" banner and could not coexist with
DevTools open on the same tab. Response body capture is planned to return as an opt-in mode.

### Network Capture Process

1. You pick a URL scope target in the popup and click Start Capture.
2. The extension resolves the in-scope host list from the target (the popup shows it) and asks the
   framework to open a session.
3. `chrome.webRequest` listeners assemble each request across its lifecycle:
   - `onBeforeRequest` (with `requestBody`) - method and request body
   - `onSendHeaders` (with `extraHeaders`) - request headers including cookies
   - `onHeadersReceived` (with `extraHeaders`) - status code and response headers
   - `onCompleted` - finalizes the record
4. Requests are filtered by **host**, not by tab, so API calls from a page service worker, OAuth
   popups, and second tabs are all captured.
5. Records are queued in `chrome.storage.session` and flushed to the framework in batches with
   retry. A slow or restarting API costs latency, not data.
6. A heartbeat every 20 seconds tells the framework the session is genuinely alive.
7. The backend stores captures in PostgreSQL and recomputes the session totals on every batch.

### Data Captured

For each HTTP request:
- Full URL and parsed endpoint path
- HTTP method (GET, POST, PUT, PATCH, DELETE, ...)
- Request headers, including `Cookie`
- Query parameters (key-value pairs)
- Request body, parsed for JSON, form-urlencoded, and multipart bodies
- Response status code and response headers, including `Set-Cookie`
- Originating tab id, or none for service-worker-issued requests
- Timestamp and MIME type

Response bodies are not captured yet.

### Endpoint Pattern Recognition

The extension recognizes patterns:
- `/api/users/123` and `/api/users/456` become `/api/users/{id}`
- `/products?id=1` and `/products?id=2` become `/products?id={value}`
- UUIDs and Mongo ObjectIds are templated the same way

## Privacy & Security

### Data Handling

- **Local Processing**: All data is sent directly to your local Ars0n Framework instance
- **No External Services**: No data is sent to third-party servers or cloud services
- **User Control**: You control when capture starts and stops
- **Sensitive Data Warning**: Captures include session cookies and authorization headers in plain
  text. Treat the framework database as credential material.

### Best Practices

- Only use on targets you own or have explicit permission to test
- Be cautious when capturing traffic on production systems
- Review captured data for sensitive information before sharing exports
- Clear capture history when testing different targets
- Use secure connections (HTTPS) when accessing the framework remotely

## Troubleshooting

### Nothing is being captured

- Open the popup while recording. It shows the resolved **In scope** host list. If the app's API
  host is not in that list, it is not being recorded. Turn on "Include Subdomains", or pick a scope
  target whose registrable domain covers the API host.
- Check the **Pending Upload** counter. If it keeps climbing, the framework is unreachable; the
  captures are safe in the queue and will upload when it comes back.
- Check the **Status** badge. If it says Idle, the session ended. The popup reads state from the
  service worker, so this badge reflects reality rather than a stale flag.

### The framework says "No Active Recording" while the popup says Capturing

This should no longer happen. The framework decides using the extension's heartbeat, so if the
service worker dies the session is reported as stalled within 90 seconds and cleanup marks it
abandoned. If you see a disagreement, check the browser console for `[MANUAL-CRAWL]` errors.

### Connection to Framework Failed

- Verify the backend is running: `docker-compose ps`
- Confirm the Framework URL in Connection Settings (default `http://localhost`)
- Check the browser console for error messages
- Ensure no firewall is blocking the connection

### Missing Requests

- Response bodies are not captured yet
- WebSocket connections are not captured yet
- Static assets are captured by default; turn off "Capture Static Assets" to exclude images, fonts,
  and media

## Development Installation (Unpacked Extension)

1. Download the extension files to your local machine

2. Open Chrome and navigate to `chrome://extensions/`

3. Enable "Developer mode" using the toggle in the top-right corner

4. Click "Load unpacked"

5. Select the `extension` folder from your Ars0n Framework directory

6. The Ars0n Framework icon should appear in your Chrome toolbar

7. Pin the extension for easy access (click the puzzle piece icon → pin)

## Usage

### Initial Setup

1. Start the Ars0n Framework v2 on your machine

2. Create a URL-type scope target in the framework

3. Navigate to the Manual Crawling section for that target

4. Click "Start Manual Crawl" in the framework

### Capturing Traffic

1. Click the Ars0n Framework extension icon in Chrome

2. Click "Start Capture"

3. Browse to your target URL and interact with the application normally:
   - Log in with valid credentials
   - Click through different pages and features
   - Submit forms
   - Trigger AJAX requests
   - Explore authenticated areas
   - Test different user roles/permissions

4. Watch the live counter showing captured requests

5. When finished exploring, click "Stop Capture"

6. Return to the Ars0n Framework to view all discovered endpoints

### Viewing Results

All captured endpoints are automatically stored in your Ars0n Framework database and can be viewed in the Manual Crawling Results section, including:

- Full endpoint URLs and paths
- HTTP methods used
- Query parameters discovered
- Request/response headers
- Status codes
- Timestamps
- Organized by endpoint patterns (e.g., `/api/users/{id}`)

## Configuration

### Target URL

The extension automatically detects the active target from your Ars0n Framework. You can also manually set the target URL in the extension popup if needed.

### Scope Settings

- **Include Subdomains**: Capture requests to all subdomains of the target
- **Capture Static Assets**: Include CSS, JavaScript, images, and other static files
- **Capture External Requests**: Include requests to third-party domains (CDNs, APIs)

### Framework Connection

By default, the extension connects to `http://localhost` (the nginx reverse proxy automatically routes to the backend API). 

**To configure a different URL:**
1. Click the extension icon
2. Click "Connection Settings"
3. Enter your framework URL (e.g., `http://192.168.1.100:8000` or `https://your-server.com:8000`)
4. Click "Save Settings"
5. The extension will test the connection automatically

**Supported URL formats:**
- `http://localhost` (default - nginx handles routing)
- `http://192.168.1.100` (local network)
- `https://remote-server.com` (remote server)
- Custom port: `http://localhost:8080` (if running on non-standard port)

## Technical Architecture

### Chrome APIs Used

- **chrome.debugger**: Attaches to Chrome DevTools Protocol for comprehensive network access
- **chrome.tabs**: Manages tab state and target tracking
- **chrome.storage**: Persists configuration and capture state
- **chrome.runtime**: Handles background service worker communication

### Network Capture Process

1. Extension attaches Chrome Debugger API to the active tab
2. Enables Network domain in Chrome DevTools Protocol
3. Listens to network events:
   - `Network.requestWillBeSent` - Outgoing requests
   - `Network.responseReceived` - Response headers and status
   - `Network.loadingFinished` - Request completion
4. Filters requests based on target scope
5. Extracts endpoint patterns and parameters
6. Sends data to Framework backend via REST API
7. Backend deduplicates and stores in PostgreSQL

### Data Captured

For each HTTP request:
- Full URL and parsed endpoint path
- HTTP method (GET, POST, PUT, DELETE, etc.)
- Request headers
- Query parameters (key-value pairs)
- Request body (for POST/PUT/PATCH)
- Response status code
- Response headers
- Timestamp and sequence
- Referrer URL

### Endpoint Pattern Recognition

The extension intelligently recognizes patterns:
- `/api/users/123` and `/api/users/456` → `/api/users/{id}`
- `/products?id=1` and `/products?id=2` → `/products?id={value}`
- Groups similar endpoints with different parameters

## Privacy & Security

### Data Handling

- **Local Processing**: All data is sent directly to your local Ars0n Framework instance
- **No External Services**: No data is sent to third-party servers or cloud services
- **User Control**: You control when capture starts and stops
- **Sensitive Data Warning**: Be aware that the extension captures everything, including authentication tokens and sensitive data

### Best Practices

- Only use on targets you own or have explicit permission to test
- Be cautious when capturing traffic on production systems
- Review captured data for sensitive information before sharing exports
- Clear capture history when testing different targets
- Use secure connections (HTTPS) when accessing the framework remotely

## Troubleshooting

### Extension Not Capturing Requests

- Verify the Ars0n Framework is running at `http://localhost:8000`
- Check that you clicked "Start Capture" in the extension
- Ensure the target URL matches your scope settings
- Look for the debugger banner in Chrome ("Chrome is being controlled by automated software")

### Connection to Framework Failed

- Verify the backend server is running: `docker-compose ps`
- Check the browser console for error messages
- Ensure no firewall is blocking localhost connections
- Try restarting the Ars0n Framework

### Missing Requests

- Some requests may be blocked by CORS policies
- Certain websocket connections may not be captured
- Service workers might cache requests (disable in DevTools)

### Debugger Disconnected

- Chrome limits one debugger connection per tab
- Close DevTools if open on the same tab
- Try refreshing the page and restarting capture

## Development

### Building from Source

The extension is built using vanilla JavaScript (no build process required) for simplicity and maintainability.

### File Structure

```
extension/
├── manifest.json          # Extension configuration and permissions
├── background.js          # Service worker for network capture
├── popup.html            # Extension popup UI
├── popup.js              # Popup logic and user interactions
├── content.js            # Content script (optional, for page integration)
├── styles.css            # Popup styling
├── icons/                # Extension icons (16, 48, 128px)
└── README.md            # This file
```

### Testing

1. Make changes to extension files
2. Go to `chrome://extensions/`
3. Click the refresh icon on the Ars0n Framework extension card
4. Test changes immediately

### API Endpoints

The extension communicates with these framework endpoints:

- `POST /api/manual-crawl/start` - Initialize capture session
- `POST /api/manual-crawl/capture` - Send captured request data
- `POST /api/manual-crawl/stop` - End capture session
- `GET /api/manual-crawl/stats` - Retrieve capture statistics

## Roadmap

Future enhancements planned:

- Firefox extension support
- Advanced filtering rules (regex patterns)
- Request replay functionality
- Export captured traffic to HAR format
- Integration with Burp Suite import
- Custom payload injection for testing
- Automated authentication flow recording

## License

This extension is part of the Ars0n Framework v2 and is licensed under the GNU General Public License v3.0 (GPL-3.0).

## Support

For issues, questions, or feature requests related to the Manual Crawling Extension:

- Open an issue on the [Ars0n Framework GitHub repository](https://github.com/R-s0n/ars0n-framework-v2)
- Include "[Extension]" in your issue title
- Provide Chrome version, extension version, and detailed steps to reproduce

---

<p align="center"><em>Part of the Ars0n Framework v2 - Earn While You Learn Bug Bounty Hunting</em></p>
<p align="center">Copyright (C) 2025 Arson Security, LLC</p>
