# Akira - Claude Code Adapter

## Available Skills

When the user is working on security testing, bug bounty, CTF, or pentesting, activate the relevant Akira skill.

| User asks about | Use skill |
|---|---|
| Starting a pentest, new target, new engagement | `/plan-engagement` |
| Recon, subdomains, live hosts, phase 1 | `/recon` |
| Secrets, API keys, tokens, credentials, phase 2 | `/secrets` |
| XSS, SQLi, nuclei, exploitation, phase 3 | `/exploit` |
| Zero-days, chain attacks, WAF bypass, advanced | `/zerodayhunt` |
| Aggregating findings, triage, severity | `/triage` |
| Writing report, generating report, phase 5 | `/report` |
| Active Directory, BloodHound, Kerberoast, DCSync | `/ad-attacks` |
| OAuth, OIDC, SSO, account takeover | `/oauth-attacks` |
| Race conditions, concurrent requests, double-spend | `/race-conditions` |
| AWS, GCP, Azure, K8s, cloud audit | `/cloud-audit` |
| CTF, HackTheBox, TryHackMe, pwn, reverse | `/ctf` |

## Phase Order

```
/plan-engagement -> /recon -> /secrets -> /exploit -> /zerodayhunt -> /triage -> /report
```

## Phase Artifacts (read by each phase)

```
session.json          <- initialized by plan-engagement, updated by every phase
interesting_recon.md  <- written by recon, read by secrets + exploit
interesting_secrets.md <- written by secrets, read by exploit + zerodayhunt
interesting_exploit.md <- written by exploit, read by triage
interesting_*.md      <- all read by triage
triage.md             <- read by report
```

## Evidence Rule

**NEVER claim a finding without quoting the exact HTTP response that proves it.**

- Empty 200 body = WAF catch-all = NOT a finding
- `{"status":403}` in 200 = WAF block = NOT a finding
- A header existing does not mean it is exploitable

## Authorization

Only use on authorized targets: bug bounty programs, authorized pentests, CTF competitions.
