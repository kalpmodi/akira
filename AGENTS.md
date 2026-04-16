# Akira - AI Agent Adapter

Akira is an offensive security skill suite for AI agents.
This file enables any AI agent to discover and use Akira's skills.

## What Akira Does

Akira runs a complete pentest engagement chain:

```
plan-engagement -> recon -> secrets -> exploit -> zerodayhunt -> triage -> report
```

Plus specialized modules: ad-attacks, oauth-attacks, race-conditions, cloud-audit, ctf.

## Skill Index

| Skill file | Purpose |
|---|---|
| `skills/plan-engagement/SKILL.md` | Scope target, initialize PTT and session.json |
| `skills/recon/SKILL.md` | Subdomain enum, live hosts, ports, tech stack |
| `skills/secrets/SKILL.md` | API keys, tokens, credentials in source/JS/git |
| `skills/exploit/SKILL.md` | XSS, SQLi, nuclei, deserialization, SSTI, XXE |
| `skills/zerodayhunt/SKILL.md` | Chain attacks, JWT confusion, SSRF->cloud, WAF bypass |
| `skills/triage/SKILL.md` | Severity clustering, confidence scoring, FP gate |
| `skills/report/SKILL.md` | Pentest report or bug bounty submission |
| `skills/ad-attacks/SKILL.md` | Full Active Directory compromise chain |
| `skills/oauth-attacks/SKILL.md` | OAuth/OIDC exploitation |
| `skills/race-conditions/SKILL.md` | HTTP/2 single-packet race attacks |
| `skills/cloud-audit/SKILL.md` | AWS/GCP/Azure/K8s misconfigurations |
| `skills/ctf/SKILL.md` | CTF challenge methodology |

## How to Use

To run a skill: read the skill file and follow its instructions exactly.

Example: to run recon on target.com, read `skills/recon/SKILL.md` and execute its steps.

## Phase Artifacts

Each phase reads and writes structured files:
- `session.json` - cross-phase intelligence (initialized by plan-engagement)
- `interesting_<phase>.md` - phase output consumed by downstream phases

## Evidence Rule

Every confirmed finding must quote exact HTTP response evidence. No evidence = downgrade to potential.

## For Authorized Use Only

Only use on authorized targets: bug bounty programs, authorized pentests, CTF competitions.
