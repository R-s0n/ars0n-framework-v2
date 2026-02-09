# Manual Crawling Extension - Implementation Summary

## Overview

The Manual Crawling feature has been fully implemented with both the Chrome extension (frontend) and the Go backend API (server-side). This allows users to manually browse a target application while the extension captures all HTTP traffic and stores it in the Ars0n Framework database.

## Components Implemented

### 1. Chrome Extension (`/extension`)

**Files Created:**
- `manifest.json` - Extension configuration with necessary permissions
- `popup.html` - User interface for the extension popup
- `popup.js` - Frontend logic for user interactions
- `styles.css` - Dark theme styling matching the framework
- `background.js` - Service worker that captures network traffic
- `icons/README.md` - Guide for creating extension icons
- `README.md` - Comprehensive documentation

**Features:**
- Target URL configuration
- Real-time traffic capture using Chrome Debugger API
- Live statistics (request count, unique endpoints)
- Smart endpoint pattern recognition (e.g., `/api/users/123` → `/api/users/{id}`)
- Filtering options (subdomains, static assets)
- Automatic deduplication of endpoints
- Framework connection health check
- Configurable framework URL (supports remote servers, custom ports)

### 2. Backend API (`/server`)

**Files Created/Modified:**

`server/utils/manualCrawlUtils.go` - Complete API handler implementation:
- `HealthCheck` - Health endpoint for extension to verify connection
- `StartManualCrawl` - Initialize a new capture session
- `CaptureManualCrawlRequest` - Store individual HTTP requests
- `StopManualCrawl` - End capture session and save statistics
- `GetManualCrawlSessions` - Retrieve all sessions for a target
- `GetManualCrawlCaptures` - Get all captured requests for a session
- `GetManualCrawlEndpoints` - Get unique endpoints with statistics

`server/database.go` - Added two new tables:
- `manual_crawl_sessions` - Stores capture session metadata
- `manual_crawl_captures` - Stores individual HTTP requests

`server/main.go` - Registered new API routes:
- `GET /health`
- `POST /manual-crawl/start`
- `POST /manual-crawl/capture`
- `POST /manual-crawl/stop`
- `GET /manual-crawl/sessions/{scope_target_id}`
- `GET /manual-crawl/captures/{session_id}`
- `GET /manual-crawl/endpoints/{scope_target_id}`

### 3. Frontend Integration (`/client`)

`client/src/App.js` - Added Manual Crawling card:
- New section between "Threat Modeling" and "URL Discovery"
- "This section is still under development" banner
- Placeholder for future buttons and functionality

## Database Schema

### manual_crawl_sessions
```sql
- id (UUID, Primary Key)
- scope_target_id (UUID, Foreign Key)
- target_url (TEXT)
- status (VARCHAR)
- started_at (TIMESTAMP)
- ended_at (TIMESTAMP)
- request_count (INTEGER)
- endpoint_count (INTEGER)
- created_at (TIMESTAMP)
```

### manual_crawl_captures
```sql
- id (UUID, Primary Key)
- session_id (UUID, Foreign Key)
- scope_target_id (UUID, Foreign Key)
- url (TEXT)
- endpoint (TEXT)
- method (VARCHAR)
- status_code (INTEGER)
- headers (JSONB)
- response_headers (JSONB)
- post_data (TEXT)
- timestamp (TIMESTAMP)
- mime_type (TEXT)
- created_at (TIMESTAMP)
```

## How It Works

### Capture Flow

1. **User starts capture in extension**
   - Clicks "Start Capture" in extension popup
   - Extension sends POST to `/api/manual-crawl/start` with target URL
   - Backend creates a new session and scope target (if needed)

2. **User browses the target application**
   - Extension attaches Chrome Debugger API to the active tab
   - Listens to all network events (requestWillBeSent, responseReceived, etc.)
   - Filters requests based on target domain and settings

3. **Requests are captured and sent to backend**
   - For each matching request, extension sends POST to `/api/manual-crawl/capture`
   - Backend stores request details in `manual_crawl_captures` table
   - Endpoint patterns are extracted (IDs, UUIDs replaced with placeholders)

4. **User stops capture**
   - Clicks "Stop Capture" in extension
   - Extension sends POST to `/api/manual-crawl/stop` with final statistics
   - Backend updates session status and counts

### Smart Endpoint Recognition

The extension automatically recognizes and normalizes endpoint patterns:
- `/api/users/123` → `/api/users/{id}`
- `/api/users/550e8400-e29b-41d4-a716-446655440000` → `/api/users/{uuid}`
- `/products?id=1&category=2` → `/products?id={value}&category={value}`

## Next Steps (To Be Implemented)

### Extension Icon
- Create 16x16, 48x48, and 128x128 PNG icons
- Use Ars0n branding (red flame, dark background)
- See `/extension/icons/README.md` for guidance

### Frontend UI
Add buttons to the Manual Crawling card in `App.js`:
- "Start Manual Crawl" - Opens instructions modal
- "View Sessions" - Shows capture history
- "View Endpoints" - Displays discovered endpoints table
- Integration with existing target URLs view

### Results Display Modals
Create React components:
- `ManualCrawlSessionsModal.js` - List of capture sessions
- `ManualCrawlCapturesModal.js` - Detailed request/response viewer
- `ManualCrawlEndpointsModal.js` - Unique endpoints with statistics

### Advanced Features
- Request replay functionality
- Export to HAR format
- Integration with Burp Suite import
- Parameter extraction and analysis
- Authentication flow recording

## Configuration

### Framework URL Settings

The extension supports connecting to the framework on:
- **Local machine**: `http://localhost` (default - nginx reverse proxy)
- **Local network**: `http://192.168.1.100`
- **Remote server**: `https://your-server.com`
- **Custom port**: `http://localhost:8080` (if not using standard ports)

To change the framework URL:
1. Open the extension popup
2. Click "Connection Settings"
3. Enter your framework URL
4. Click "Save Settings"
5. Connection is tested automatically

Settings are persisted in Chrome's local storage and survive browser restarts.

## Testing

### Prerequisites
1. Ars0n Framework v2 running (default: `http://localhost` via nginx)
2. Chrome browser (version 88+)

### Steps to Test

1. **Build and restart the framework**
   ```bash
   docker-compose down
   docker-compose up --build
   ```

2. **Load the extension**
   - Open Chrome and navigate to `chrome://extensions/`
   - Enable "Developer mode"
   - Click "Load unpacked"
   - Select the `/extension` folder
   - (You'll need to add placeholder icon files first)

3. **Create a URL scope target**
   - Open Ars0n Framework at `http://localhost`
   - Create a new URL-type scope target (or the extension will create one automatically)

4. **Test the capture flow**
   - Click the extension icon
   - Enter a target URL (e.g., `https://example.com`)
   - Click "Start Capture"
   - Browse the target site
   - Observe live statistics updating
   - Click "Stop Capture"

5. **Verify in database**
   ```sql
   SELECT * FROM manual_crawl_sessions;
   SELECT * FROM manual_crawl_captures;
   ```

## API Endpoints Reference

### POST /api/manual-crawl/start
```json
Request:
{
  "targetUrl": "https://example.com"
}

Response:
{
  "success": true,
  "sessionId": "uuid",
  "scopeTargetId": "uuid"
}
```

### POST /api/manual-crawl/capture
```json
Request:
{
  "url": "https://example.com/api/users/123",
  "endpoint": "/api/users/{id}",
  "method": "GET",
  "statusCode": 200,
  "headers": {},
  "responseHeaders": {},
  "timestamp": "2025-01-30T...",
  "mimeType": "application/json"
}

Response:
{
  "success": true,
  "captureId": "uuid"
}
```

### POST /api/manual-crawl/stop
```json
Request:
{
  "stats": {
    "requestCount": 42,
    "endpointCount": 15
  }
}

Response:
{
  "success": true,
  "sessionId": "uuid"
}
```

### GET /api/manual-crawl/sessions/{scope_target_id}
```json
Response: [
  {
    "id": "uuid",
    "scope_target_id": "uuid",
    "target_url": "https://example.com",
    "status": "completed",
    "started_at": "2025-01-30T...",
    "ended_at": "2025-01-30T...",
    "request_count": 42,
    "endpoint_count": 15
  }
]
```

### GET /api/manual-crawl/captures/{session_id}
Returns array of all captured HTTP requests for a session.

### GET /api/manual-crawl/endpoints/{scope_target_id}
```json
Response: [
  {
    "endpoint": "/api/users/{id}",
    "method": "GET",
    "request_count": 5,
    "first_seen": "2025-01-30T...",
    "last_seen": "2025-01-30T..."
  }
]
```

## Architecture Decisions

### Why Chrome Debugger API?
- Full access to all network traffic (including WebSockets, redirects)
- Captures request/response bodies
- No proxy configuration needed
- Direct integration with Chrome DevTools Protocol

### Why Session-Based Design?
- Allows multiple capture sessions for the same target
- Historical tracking of reconnaissance activities
- Easy to organize and review past captures
- Supports collaborative work (share sessions)

### Why Pattern Recognition?
- Reduces duplicate endpoint storage
- Makes analysis easier (group similar requests)
- Better for reporting and visualization
- Industry-standard approach (similar to Burp Suite)

## Known Limitations

1. **Browser-Specific**: Currently Chrome-only (Firefox support planned)
2. **No Request Modification**: Capture-only, no request replay or modification yet
3. **Memory Constraints**: Very large captures may impact performance
4. **Single Active Session**: Only one capture session can be active at a time
5. **No Authentication Storage**: Tokens/credentials are captured but not managed

## Contributing

Future enhancements welcome:
- Firefox extension port
- Advanced filtering rules
- Request replay functionality
- HAR export format
- Burp Suite integration
- Custom payload injection

---

**Status**: Backend API ✅ Complete | Chrome Extension ✅ Complete | Frontend UI ⏳ Pending | Icons ⏳ Pending

**Version**: 1.0.0 (Beta)

**Last Updated**: January 30, 2025
