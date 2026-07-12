# SSRF to AWS IMDSv1 Credential Extraction

## Attack Surface

Server-side URL fetch/proxy features that can reach link-local metadata endpoints.

## Preconditions

- Request handler fetches attacker-controlled URL
- Outbound egress allows `169.254.169.254`
- Workload uses IMDSv1 (no session token required)

## Reproduction Outline

1. Identify proxy/fetch endpoint (example: `/api/proxy?url=`)
2. Request IAM role listing endpoint through SSRF
3. Request role credential endpoint through SSRF
4. Validate temporary credentials against cloud APIs

## Evidence Pattern

```http
GET /api/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/role

HTTP/1.1 200 OK
{"AccessKeyId":"ASIA...","SecretAccessKey":"...","Token":"..."}
```

## True Positive vs False Positive

- **True positive:** valid IAM credential document returned and usable
- **False positive:** metadata unreachable, blocked, or fake static response

## Mitigation

- Enforce IMDSv2 on AWS workloads
- Block link-local metadata ranges from application egress
- Strict allowlist for URL fetch destinations
