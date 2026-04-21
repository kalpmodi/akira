<div align="center">

<img src="assets/banner.svg" alt="AKIRA - AI Pentest Co-Pilot" width="900"/>

[![Typing SVG](https://readme-typing-svg.demolab.com?font=Fira+Code&weight=700&size=18&duration=2500&pause=800&color=00FF41&center=true&vCenter=true&width=700&lines=Phase-chained.+Evidence-gated.+No+hallucinations.;Native+in+Claude+Code%2C+Gemini+CLI%2C+Cursor%2C+Codex;12+attack+modules.+Real+bug+bounty+proof.;plan-engagement+%E2%86%92+recon+%E2%86%92+secrets+%E2%86%92+exploit+%E2%86%92+report)](https://github.com/Kalp1774/akira)

[![GitHub Stars](https://img.shields.io/github/stars/Kalp1774/akira?style=flat-square&color=yellow)](https://github.com/Kalp1774/akira/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/Kalp1774/akira?style=flat-square&color=blue)](https://github.com/Kalp1774/akira/network/members)
[![GitHub Issues](https://img.shields.io/github/issues/Kalp1774/akira?style=flat-square&color=red)](https://github.com/Kalp1774/akira/issues)
[![Last Commit](https://img.shields.io/github/last-commit/Kalp1774/akira?style=flat-square&color=green)](https://github.com/Kalp1774/akira/commits/main)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)
[![Skills](https://img.shields.io/badge/skills-12-brightgreen?style=flat-square)](#skills)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square)](CONTRIBUTING.md)

**[Install in 30 seconds](#install) · [Real Findings](#proof-it-works) · [Roadmap](#roadmap) · [Wiki](../../wiki)**

</div>

---

## What Is Akira?

A complete offensive security skill suite that runs **natively inside your AI coding environment** - Claude Code, Gemini CLI, Cursor, Codex, or any agent.

No server. No 40-tool pre-install hell. No hallucinated findings. Every finding requires direct HTTP evidence. No proof = no finding.

```
/plan-engagement → /recon → /secrets → /exploit → /zerodayhunt → /triage → /report
```

---

## Install

```bash
git clone https://github.com/Kalp1774/akira
cd akira && bash install.sh
```

To also install tools (nuclei, dalfox, subfinder, httpx, sqlmap...):

```bash
bash install.sh && bash bootstrap.sh
```

Open Claude Code, type `/plan-engagement target.com`, and go.

Full installation guide and platform setup in the [Wiki - Installation](../../wiki/Installation).

---

## Skills

Full technique details and examples in the [Wiki - Skills](../../wiki/Skills).

### Core 7-Phase Lifecycle

| Skill | Phase | What It Does |
|---|---|---|
| `/plan-engagement` | 0 | Scope definition, PTT generation, session.json init |
| `/recon` | 1 | Subdomains, live hosts, ports, URLs, tech stack fingerprint |
| `/secrets` | 2 | API keys, tokens, credentials in JS/source/git/Postman |
| `/exploit` | 3 | XSS, SQLi, nuclei, deserialization, SSTI, XXE, NoSQLi |
| `/zerodayhunt` | 3+ | JWT confusion, SSRF->IAM, WAF bypass, type juggling |
| `/triage` | 4 | Severity clustering, confidence scoring (0-100), FP gate |
| `/report` | 5 | Pentest report or HackerOne/Bugcrowd submission format |

### Specialized Attack Modules

Full attack technique walkthroughs in the [Wiki - Attack Techniques](../../wiki/Attack-Techniques).

| Skill | What It Does |
|---|---|
| `/ad-attacks` | BloodHound, Kerberoasting, DCSync, Golden/Silver Ticket, ADCS ESC1-8 |
| `/oauth-attacks` | Redirect URI bypass, CSRF, PKCE downgrade, JWT confusion |
| `/race-conditions` | HTTP/2 single-packet attack, coupon reuse, double-spend, OTP bypass |
| `/cloud-audit` | AWS SSRF->IAM, S3 enum, GCP, Azure, K8s unauthenticated API |
| `/ctf` | HackTheBox/TryHackMe - web/crypto/pwn/RE/forensics/OSINT/stego |

---

## Proof It Works

Real anonymized findings made with Akira. Full writeups in [FINDINGS.md](FINDINGS.md).

| # | Type | Severity | Bounty | Skill Chain |
|---|---|---|---|---|
| 1 | SSRF → AWS IAM Credential Extraction | Critical | $2,500 | `/recon` → `/exploit` → `/cloud-audit` |
| 2 | OAuth Open Redirect → Auth Code Interception | Critical | $1,800 | `/recon` → `/oauth-attacks` |
| 3 | Race Condition: Coupon Applied 7x | High | $800 | `/race-conditions` |
| 4 | Strapi SSRF Bypass + MIME Fail-Open (CVE filed) | Critical | - | `/zerodayhunt` |
| 5 | JWT RS256→HS256 Confusion → Admin Access | Critical | $1,500 | `/zerodayhunt` |

---

## Why Not PentestGPT?

| Capability | PentestGPT | HexStrike | **Akira** |
|---|:---:|:---:|:---:|
| Full 6-phase engagement lifecycle | Partial | - | **YES** |
| Phase artifact handoffs (session.json) | - | - | **YES** |
| Anti-hallucination evidence gate | - | - | **YES** |
| Confidence scoring per finding (0-100) | - | - | **YES** |
| AD full chain (BloodHound → DCSync) | - | Partial | **YES** |
| OAuth/OIDC exploitation suite | - | - | **YES** |
| Race conditions (single-packet attack) | - | - | **YES** |
| Cloud audit (AWS + GCP + Azure + K8s) | - | Partial | **YES** |
| CTF mode (HackTheBox, TryHackMe) | **YES** | - | **YES** |
| Native in Claude Code, Gemini, Cursor | Partial | - | **YES** |
| Free + MIT | **YES** | Partial | **YES** |

---

## Roadmap

See the full roadmap in the [Wiki](../../wiki/Roadmap).

| Release | ETA | New Skills |
|---|---|---|
| **Hydra v1.0.0** | Shipped | 12 core skills |
| Basilisk v1.1.0 | Month 2 | `graphql`, `deserialization`, `prototype-pollution`, `supply-chain`, `ci-cd-audit` |
| Raven v1.2.0 | Month 3 | Akira Context Engine, `cache-attacks`, `csp-bypass` |
| Phantom v1.3.0 | Month 4 | `mobile`, `burp-integration` |
| Leviathan v2.0.0 | Month 6 | Akira Brain, `postmap-recon`, `red-team` |

---

## Contributing

Found a technique that belongs in Akira? Fix a skill bug? Submit a real finding?

See [CONTRIBUTING.md](CONTRIBUTING.md) and the [Wiki - Contributing](../../wiki/Contributing) - PRs welcome, fast review.

---

## Legal

For **authorized security testing only** - bug bounty programs, systems you own, CTF competitions.

Unauthorized testing is illegal. Authors not responsible for misuse.

---

<div align="center">

Built for bug hunters, by bug hunters.

**[Star this repo](https://github.com/Kalp1774/akira) to stay updated when new skills ship.**

</div>
