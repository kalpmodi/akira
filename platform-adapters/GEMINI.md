# Akira - Gemini CLI Adapter

## Setup

Add this file to your Gemini CLI skills path, or append its contents to your existing `GEMINI.md`.

## Available Skills

Akira provides 12 offensive security skills. Activate them when the user is working on security testing.

| Skill | Activate when user asks about |
|---|---|
| `plan-engagement` | Starting a pentest, scoping a target, new engagement |
| `recon` | Subdomain enumeration, live hosts, phase 1, recon |
| `secrets` | API keys, tokens, credentials, secrets hunting, phase 2 |
| `exploit` | XSS, SQL injection, nuclei, exploitation, phase 3 |
| `zerodayhunt` | Zero-days, chain attacks, WAF bypass, JWT, SSRF chains |
| `triage` | Aggregating findings, severity clustering, phase 4 |
| `report` | Writing pentest report, HackerOne submission, phase 5 |
| `ad-attacks` | Active Directory, BloodHound, Kerberoast, DCSync, lateral movement |
| `oauth-attacks` | OAuth, OIDC, SSO, redirect URI bypass, account takeover |
| `race-conditions` | Race conditions, concurrent requests, double-spend, TOCTOU |
| `cloud-audit` | AWS, GCP, Azure, Kubernetes, cloud misconfiguration |
| `ctf` | CTF, HackTheBox, TryHackMe, pwn, reverse engineering, forensics |

## Skill Files

All skills are in `skills/<skill-name>/SKILL.md` relative to this repo root.

## Phase Chain

```
plan-engagement -> recon -> secrets -> exploit -> zerodayhunt -> triage -> report
```

## Evidence Requirement

Every finding must include the exact HTTP request/response proving it. No evidence = not a finding.

## Authorization

Authorized targets only: bug bounty programs, authorized pentests, CTF competitions.
