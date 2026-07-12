# interesting_recon.md

## Summary
- Recon completed for `example.com`.
- 3 live hosts discovered and prioritized.

## Confirmed Findings
- Open directory listing on `cdn.example.com/assets/`.
- Exposed debug endpoint on `api.example.com/debug`.

## Potential Findings
- Suspected SSRF behavior on `/api/proxy?url=`.
- Potential open redirect on `/redirect?url=`.

## Evidence Snippets
```http
GET /api/proxy?url=http://example.org HTTP/1.1
Host: api.example.com

HTTP/1.1 200 OK
```

## Next Actions
- Run `/secrets example.com`.
- Run `/exploit example.com`.
