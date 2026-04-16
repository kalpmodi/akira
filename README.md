<div align="center">

```
 █████╗ ██╗  ██╗██╗██████╗  █████╗
██╔══██╗██║ ██╔╝██║██╔══██╗██╔══██╗
███████║█████╔╝ ██║██████╔╝███████║
██╔══██║██╔═██╗ ██║██╔══██╗██╔══██║
██║  ██║██║  ██╗██║██║  ██║██║  ██║
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
```

**The AI Pentest Co-Pilot That Actually Finds Bugs**

*Phase-chained. Evidence-gated. Native in Claude Code, Gemini CLI, Cursor, Codex, and more.*

[![GitHub Stars](https://img.shields.io/github/stars/Kalp1774/akira?style=flat-square&color=yellow)](https://github.com/Kalp1774/akira/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/Kalp1774/akira?style=flat-square&color=blue)](https://github.com/Kalp1774/akira/network/members)
[![GitHub Issues](https://img.shields.io/github/issues/Kalp1774/akira?style=flat-square&color=red)](https://github.com/Kalp1774/akira/issues)
[![Last Commit](https://img.shields.io/github/last-commit/Kalp1774/akira?style=flat-square&color=green)](https://github.com/Kalp1774/akira/commits/main)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)
[![Skills](https://img.shields.io/badge/skills-12-brightgreen?style=flat-square)](#skills)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square)](CONTRIBUTING.md)

**[Install in 30 seconds](#install) - [See Real Findings](#proof-it-works) - [Compare vs Competitors](#why-not-pentestgpt) - [Roadmap](#roadmap)**

</div>

> **Demo:** Run `bash demo/simulate.sh` to see a full engagement walkthrough in your terminal.
> Record your own GIF with `vhs demo.tape` ([install vhs](https://github.com/charmbracelet/vhs)).

---

## What Is Akira?

Akira is a complete offensive security skill suite that runs **natively inside your AI coding environment**.

No Docker. No server. No 40-tool pre-install hell. No hallucinated findings.

**Six phases. One chain. One deliverable report.**

```
/plan-engagement -> /recon -> /secrets -> /exploit -> /zerodayhunt -> /triage -> /report
```

Each phase reads structured output from the previous phase and writes for the next.
Every finding requires direct HTTP evidence. No proof = no finding. Always.

---

## Why Not PentestGPT?

PentestGPT has 12k stars and a documented hallucination problem.
HexStrike has tool coverage but no phase handoffs.
Trail of Bits has CI/CD coverage but no engagement lifecycle.

**Akira has all of it - and none of their weaknesses.**

| Capability | PentestGPT | HexStrike | Trail of Bits | **Akira** |
|---|:---:|:---:|:---:|:---:|
| Full 6-phase engagement lifecycle | Partial | - | - | **YES** |
| Phase artifact handoffs (session.json) | - | - | - | **YES** |
| Anti-hallucination evidence gate | - | - | - | **YES** |
| Confidence scoring per finding (0-100) | - | - | - | **YES** |
| False positive verification gate | - | - | Partial | **YES** |
| Active Directory full chain (BloodHound -> DCSync) | - | Partial | - | **YES** |
| OAuth/OIDC exploitation suite | - | - | - | **YES** |
| Race conditions (single-packet attack) | - | - | - | **YES** |
| Cloud audit (AWS + GCP + Azure + K8s) | - | Partial | - | **YES** |
| CI/CD GitHub Actions attack vectors | - | - | **YES** | Coming Month 2 |
| CTF mode (HackTheBox, TryHackMe) | **YES** | - | - | **YES** |
| Native in Claude Code, Gemini, Cursor | Partial | - | - | **YES** |
| One-command tool bootstrap | - | - | - | **YES** |
| Real bug bounty proof (updated weekly) | - | - | - | **YES** |
| Free + MIT | **YES** | Partial | **YES** | **YES** |

---

## Install

**Option 1 - Clone and install skills (recommended):**

```bash
git clone https://github.com/Kalp1774/akira
cd akira && bash install.sh
```

**Option 2 - Install tools too (nuclei, dalfox, subfinder, etc.):**

```bash
git clone https://github.com/Kalp1774/akira
cd akira && bash install.sh && bash bootstrap.sh
```

That's it. Open Claude Code (or your AI environment), type `/plan-engagement target.com`, and go.

**Verify install:**

```
/plan-engagement example.com
```

You should see the engagement plan and session.json initialized.

---

## Platform Support

| Platform | Install | Skill Syntax |
|---|---|---|
| **Claude Code** | `install.sh` copies to `~/.claude/skills/` | `/plan-engagement`, `/recon`, etc. |
| **Gemini CLI** | Add `platform-adapters/GEMINI.md` to skills path | `activate_skill plan-engagement` |
| **Cursor** | Copy `platform-adapters/.cursor/rules/akira.mdc` | Cursor rules auto-activate |
| **Codex (OpenAI)** | See `platform-adapters/.codex/INSTALL.md` | Reference via AGENTS.md |
| **GitHub Copilot CLI** | AGENTS.md pattern | Natural language trigger |
| **Any agent** | AGENTS.md in repo root | Plain text skill invocation |

---

## Skills

### Core 7-Phase Lifecycle

| Skill | Phase | What It Does |
|---|---|---|
| `/plan-engagement` | 0 | Scope definition, PTT generation, session.json init |
| `/recon` | 1 | Subdomains, live hosts, ports, URLs, tech stack fingerprint |
| `/secrets` | 2 | API keys, tokens, credentials in JS/source/git/Postman |
| `/exploit` | 3 | XSS (dalfox), SQLi (sqlmap), nuclei scan, deserialization, SSTI, XXE, NoSQLi |
| `/zerodayhunt` | 3+ | Chain attacks, JWT confusion, SSRF->IAM, WAF bypass, type juggling |
| `/triage` | 4 | Severity clustering, confidence scoring, FP verification, deduplication |
| `/report` | 5 | Pentest report or HackerOne/Bugcrowd submission format |

### Specialized Attack Modules

| Skill | What It Does |
|---|---|
| `/ad-attacks` | BloodHound path analysis, Kerberoasting, AS-REP, DCSync, Golden/Silver Ticket, ADCS ESC1-8 |
| `/oauth-attacks` | Redirect URI bypass, CSRF on OAuth, PKCE downgrade, JWT confusion, implicit flow token theft |
| `/race-conditions` | HTTP/2 single-packet attack, coupon reuse, double-spend, OTP bypass, TOCTOU |
| `/cloud-audit` | AWS SSRF->IAM, S3 enum, IAM privesc, GCP service account, Azure RBAC, K8s API |
| `/ctf` | HackTheBox/TryHackMe, web/crypto/pwn/RE/forensics/OSINT/stego methodology |

---

## How the Phase Chain Works

Every skill reads structured output from the previous phase. No intelligence is lost between phases.

```
plan-engagement
  writes -> session.json     (target, scope, tech stack, attack priority tree)

recon
  reads  -> session.json
  writes -> interesting_recon.md    (live hosts, ports, URLs, headers)

secrets
  reads  -> interesting_recon.md
  writes -> interesting_secrets.md  (verified API keys, tokens, credentials)

exploit
  reads  -> interesting_recon.md + interesting_secrets.md
  writes -> interesting_exploit.md  (confirmed vulns with HTTP evidence)

zerodayhunt
  reads  -> ALL prior outputs
  writes -> interesting_zerodayhunt.md  (chains, zero-days, critical paths)

triage
  reads  -> ALL interesting_*.md files
  writes -> triage.md  (severity-clustered, confidence-scored, FP-verified)

report
  reads  -> triage.md + session.json
  writes -> report-YYYY-MM-DD.md  (final deliverable)
```

---

## Anti-Hallucination System

Akira's biggest technical differentiator. Every finding must pass the evidence gate before it reaches the report.

**Evidence Requirements (enforced in every skill):**
- Every CONFIRMED finding must quote the exact HTTP response body proving it
- Empty 200 response body = WAF catch-all = NOT a finding
- `{"status":403}` in a 200 response = WAF block = NOT a finding
- A header existing does not mean the header is exploitable

**Confidence Scoring (0-100):**

| Score | Meaning |
|---|---|
| 90-100 | Reproducible, full data exfil or proven RCE |
| 70-89 | Strong evidence, not fully chained yet |
| 50-69 | Behavioral indicator, no data proof |
| < 50 | Speculative - auto-excluded from report |

Findings below 70 are automatically downgraded to POTENTIAL and excluded from final report.

---

## Proof It Works

Real anonymized findings made with Akira. Updated weekly.

> See [FINDINGS.md](FINDINGS.md) for full writeups.

| # | Type | Severity | Platform | Bounty | Skill Chain |
|---|---|---|---|---|---|
| 1 | SSRF -> AWS IAM Credential Extraction | Critical | HackerOne | $2,500 | `/recon` -> `/exploit` -> `/cloud-audit` |
| 2 | OAuth Open Redirect -> Authorization Code Interception | Critical | Bugcrowd | $1,800 | `/recon` -> `/oauth-attacks` |
| 3 | Race Condition: Coupon Applied 7x Simultaneously | High | Private | $800 | `/race-conditions` |
| 4 | Strapi SSRF Bypass + MIME Fail-Open (CVE filed) | Critical | CVE | - | `/zerodayhunt` |
| 5 | JWT RS256->HS256 Algorithm Confusion -> Admin Access | Critical | HackerOne | $1,500 | `/zerodayhunt` |

---

## Roadmap

Akira ships new skills every month. Here's what's coming:

**Month 1 - SHIPPED (v1.0.0)**
- [x] Core 7-phase lifecycle
- [x] ad-attacks (BloodHound -> DCSync full chain)
- [x] oauth-attacks (open redirect -> ATO chains)
- [x] race-conditions (HTTP/2 single-packet)
- [x] cloud-audit (AWS/GCP/Azure/K8s)
- [x] ctf (HTB/THM/PicoCTF)
- [x] Phase handoff system (session.json)
- [x] Anti-hallucination evidence gate

**Month 2 - Coming**
- [ ] `graphql` - Introspection abuse, batching, field-level authz bypass
- [ ] `deserialization` - Java/PHP/Python/.NET gadget chains (ysoserial, PHPGGC)
- [ ] `prototype-pollution` - Node.js client + server RCE chains
- [ ] `supply-chain` - Dependency confusion, namespace squatting, typosquatting
- [ ] `ci-cd-audit` - 9 GitHub Actions attack vectors (Trail of Bits methodology + more)

**Month 3 - Coming**
- [ ] Akira Context Engine - auto-pulls CVEs for detected stack + HackerOne disclosed reports
- [ ] `cache-attacks` - Cache poisoning + cache deception unified playbook
- [ ] `csp-bypass` - CSP escape chains, JSONP, nonce reuse

**Month 4 - Coming**
- [ ] `mobile` - Android APK analysis, Firebase misconfig, iOS IPA, Frida certificate pinning bypass
- [ ] `burp-integration` - Native Burp Suite MCP integration (Repeater, Intruder, proxy history)

**Month 6 - Coming**
- [ ] Akira Brain - Persistent attack tree across sessions, cross-engagement memory
- [ ] `postmap-recon` - PostmapDB integration (leaked Postman collections -> live secrets)
- [ ] `red-team` - MITRE ATT&CK full emulation

---

## Sponsor

Akira is free and MIT licensed. If it helped you find a bug or win a CTF, consider supporting development:

- **GitHub Sponsors:** [@Kalp1774](https://github.com/sponsors/Kalp1774)
- **Buy Me a Coffee:** [buymeacoffee.com/kalpmodi](https://buymeacoffee.com/kalpmodi)
- **Ko-fi:** [ko-fi.com/kalpmodi](https://ko-fi.com/kalpmodi)

Every sponsorship goes directly into new skills, technique research, and real bug bounty hunting to keep FINDINGS.md alive.

---

## Contributing

Found a technique that should be in Akira? Bug in a skill? New tool that belongs here?

1. Fork the repo
2. Add or improve a skill in `skills/<skill-name>/SKILL.md`
3. Open a PR with a brief explanation of what it covers
4. If it's from a real finding - include a link to the public disclosure (anonymized is fine)

Attribution added to FINDINGS.md for all confirmed-finding contributions.

See [SECURITY.md](SECURITY.md) for how to report skill bugs, suggest techniques, or submit findings made with Akira.

---

## Listed In

> Submit Akira to these lists after launch to drive organic traffic:

- [ ] [awesome-security](https://github.com/sbilly/awesome-security) - open a PR to the Tools section
- [ ] [awesome-pentest](https://github.com/enaqx/awesome-pentest) - open a PR
- [ ] [awesome-claude-code](https://github.com/hessamoddin/awesome-claude-code) - open a PR
- [ ] [awesome-hacking](https://github.com/Hack-with-Github/Awesome-Hacking) - open a PR
- [ ] [awesome-bug-bounty](https://github.com/djadmin/awesome-bug-bounty) - open a PR
- [ ] [HackerOne Resources](https://www.hackerone.com/hackers/resources) - submit tool
- [ ] [kali.org/tools](https://www.kali.org/tools/) - longer term goal

---

## Legal

Akira is for **authorized security testing only.**

Use only on:
- Bug bounty programs you are enrolled in
- Systems you own or have explicit written permission to test
- CTF competitions

Unauthorized testing is illegal. The authors are not responsible for misuse.

---

<div align="center">

Built for bug hunters, by bug hunters.

**[Star this repo](https://github.com/Kalp1774/akira) to stay updated when new skills ship.**

</div>
