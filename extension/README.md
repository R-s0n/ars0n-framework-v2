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
