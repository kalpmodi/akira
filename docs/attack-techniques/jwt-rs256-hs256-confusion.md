# JWT Algorithm Confusion (RS256 -> HS256)

## Attack Surface

Applications that trust the JWT `alg` header and accept asymmetric-to-symmetric fallback.

## Preconditions

- JWTs are signed as `RS256`
- Public key is exposed via JWKS or cert endpoint
- Verifier accepts `HS256` and does not pin algorithm server-side

## Reproduction Outline

1. Fetch public key from `/.well-known/jwks.json`
2. Convert key material to bytes and use as HMAC secret
3. Forge token header to `{"alg":"HS256","typ":"JWT"}`
4. Set privileged claims (`role=admin`) and sign token
5. Replay token against protected admin endpoint

## Evidence Pattern

```http
GET /api/admin/users HTTP/1.1
Authorization: ******

HTTP/1.1 200 OK
Content-Type: application/json
```

## True Positive vs False Positive

- **True positive:** server returns protected resource with forged token
- **False positive:** server rejects token (`401/403`) or enforces RS256 only

## Mitigation

- Enforce a fixed algorithm server-side
- Separate symmetric and asymmetric key paths
- Reject tokens with unexpected `alg` values
