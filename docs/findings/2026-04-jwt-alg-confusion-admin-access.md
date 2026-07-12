# 2026-04 - JWT RS256->HS256 Algorithm Confusion -> Admin Access

## Target Type

Anonymized SaaS platform (bug bounty scope).

## Skill Chain

`/zerodayhunt`

## Reproduction Steps

1. Capture a valid user JWT using `RS256`.
2. Pull signing public key from the JWKS endpoint.
3. Re-sign token payload with `HS256`, using public key bytes as the HMAC secret.
4. Set elevated claims in payload (`role=admin`).
5. Send forged token to admin-only endpoint.

## HTTP Evidence

```http
GET /api/admin/users HTTP/1.1
Authorization: ******

HTTP/1.1 200 OK
Content-Type: application/json

{"users":[{"id":1,"email":"admin@target.com","role":"admin"}]}
```

## Business Impact

Unauthorized administrative access with exposure of user and billing data.

## Remediation

- Enforce fixed JWT algorithm server-side.
- Reject algorithm changes from token headers.
- Add regression tests for algorithm confusion paths.
