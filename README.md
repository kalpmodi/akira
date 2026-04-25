<div align="center">

<img src="assets/banner.svg" alt="AKIRA - AI Pentest Co-Pilot" width="900"/>

[![Typing SVG](https://readme-typing-svg.demolab.com?font=Fira+Code&weight=700&size=18&duration=2500&pause=800&color=00FF41&center=true&vCenter=true&width=700&lines=Attack+Graph+Engine.+Signal-driven.+Hypothesis-ranked.;Thin+router+%2B+technique+library.+75%25+token+reduction.;Native+in+Claude+Code%2C+Gemini+CLI%2C+Cursor%2C+Codex;16+skills.+68+technique+files.+Real+bug+bounty+proof.;plan-engagement+%E2%86%92+recon+%E2%86%92+secrets+%E2%86%92+exploit+%E2%86%92+report)](https://github.com/kalpmodi/akira)

[![GitHub Stars](https://img.shields.io/github/stars/kalpmodi/akira?style=flat-square&color=yellow)](https://github.com/kalpmodi/akira/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/kalpmodi/akira?style=flat-square&color=blue)](https://github.com/kalpmodi/akira/network/members)
[![GitHub Issues](https://img.shields.io/github/issues/kalpmodi/akira?style=flat-square&color=red)](https://github.com/kalpmodi/akira/issues)
[![Last Commit](https://img.shields.io/github/last-commit/kalpmodi/akira/dev?style=flat-square&color=green)](https://github.com/kalpmodi/akira/commits/dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)
[![Skills](https://img.shields.io/badge/skills-16-brightgreen?style=flat-square)](#skills)
[![Tech Files](https://img.shields.io/badge/technique_files-68-blue?style=flat-square)](#architecture)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square)](CONTRIBUTING.md)
[![CI](https://github.com/kalpmodi/akira/actions/workflows/validate-skills.yml/badge.svg?branch=dev)](https://github.com/kalpmodi/akira/actions/workflows/validate-skills.yml)

> **You are on the `dev` branch** - this is the latest architecture. The `main` branch has the stable release.

**[Install in 30 seconds](#install) · [Real Findings](#proof-it-works) · [Architecture](#architecture) · [Roadmap](#roadmap)**

</div>

---

## What Is Akira?

A complete offensive security skill suite that runs **natively inside your AI coding environment** - Claude Code, Gemini CLI, Cursor, Codex, or any agent.

No server. No 40-tool pre-install hell. No hallucinated findings. Every finding requires direct HTTP evidence. No proof = no finding.

```
/plan-engagement → /recon → /secrets → /exploit → /zerodayhunt → /triage → /report
```

---

## What's New in Dev (Basilisk v1.1.0)

### Thin Router + Technique Library Architecture

The biggest internal upgrade since launch. Every large skill has been split into a **thin router** (~180 lines) and a **technique library** of focused per-technique files (~80 lines each).

**Before:** Invoking `/zerodayhunt` loaded all 1843 lines into context - even when you only needed SSRF.

**After:** The router reads Phase 0 intel, builds a manifest, then loads only the relevant technique files. An SSRF hunt loads ~460 lines instead of 1843. **75% token reduction per session.**

```
skills/
├── _shared/
│   ├── phase0.sh       ← canonical session state, intel relay, memory read
│   └── signals.sh      ← atomic append-only signal emission (race-proof)
│
├── zerodayhunt/
│   ├── SKILL.md        ← 179-line router (was 1843 lines)
│   └── tech/           ← 20 technique files, loaded on demand
│       ├── ssrf-oob.md
│       ├── chain-blueprints.md
│       ├── jwt-saml-sso.md
│       └── ...
```

### New Skills
- `/redteam` - Full red team: initial access, lateral movement, AD exploitation, C2, persistence, cloud APT, exfil, opsec
- `/compact` - Compresses `session.json` when it grows large mid-engagement

### Phase 0 Unified
All 15 skills now source `_shared/phase0.sh` instead of duplicated bash blocks. Intel relay is consistent across every skill - recon findings flow automatically into exploit, cloud-audit, zerodayhunt without manual re-input.

---

## Architecture

```
skills/
│
├── _shared/                    canonical shared libraries
│   ├── phase0.sh               session state, intel relay, memory read
│   └── signals.sh              append-only signals.jsonl
│
├── THIN ROUTER SKILLS (router + tech/ library)
│   ├── recon/         119-line router + 14 technique files
│   ├── exploit/       234-line router + 20 technique files
│   ├── redteam/       207-line router + 14 technique files
│   └── zerodayhunt/   179-line router + 20 technique files
│
├── SINGLE-FILE SKILLS (Phase 0 sources _shared)
│   ├── secrets/        cloud-aware credential hunting
│   ├── cloud-audit/    AWS + GCP + Azure + K8s
│   ├── 403-bypass/     29+ bypass techniques
│   ├── oauth-attacks/  OAuth 2.0 + OIDC exploitation
│   └── race-conditions/ HTTP/2 single-packet attack
│
├── ORCHESTRATION SKILLS
│   ├── plan-engagement/ hypothesis engine + state machine
│   ├── triage/          severity clustering + ATW write-back to memory
│   └── report/          formats pre-filled report_draft
│
└── ISOLATED
    ├── ctf/             HackTheBox / TryHackMe - fully isolated
    └── compact/         session.json compression
```

### How a Session Flows

```
/plan-engagement target.com
    writes session.json, sets state=WIDE, generates ranked hypotheses

/recon target.com
    router loads 3-5 technique files from recon/tech/
    emits SURFACE_FOUND + TECH_DETECTED signals
    writes intel relay to session.json

/secrets target.com
    reads recon relay -> targeted credential hunt
    AWS key found -> triggers cloud-audit fork automatically

/zerodayhunt target.com
    router reads ALL prior relays
    reprioritizes manifest: AWS+SSRF -> loads ssrf-oob.md + chain-blueprints.md
    only ~460 lines loaded vs 1843 before

/triage target.com
    certifies findings
    writes ATW (dead techniques) back to memory - skipped in future engagements

/report target.com
    formats pre-filled report_draft - findings written on confirmation, not here
```

---

## Install

```bash
git clone https://github.com/kalpmodi/akira
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

### Core 7-Phase Lifecycle

| Skill | Phase | What It Does |
|---|---|---|
| `/plan-engagement` | 0 | Inference-first init: ranked hypotheses, signal bus, WIDE/DEEP/HARVEST/WRAP state machine, fork scheduler |
| `/recon` | 1 | 23-step pipeline across 14 technique files - hypothesis-driven ordering, emits SURFACE_FOUND + TECH_DETECTED + WAF_CONFIRMED |
| `/secrets` | 2 | Hypothesis-targeted credential scan - CRED_FOUND/JWT_FOUND, AWS key triggers cloud-audit fork |
| `/exploit` | 3 | 20 technique files - tests top-probability hypothesis first, writes report_draft on confirmation |
| `/zerodayhunt` | 3+ | 20 technique files - 32 phases: JWT confusion, SSRF->IAM, WAF bypass, chain blueprints, conference-grade attacks |
| `/triage` | 4 | Severity clustering, confidence scoring (0-100), FP gate, ATW write-back |
| `/report` | 5 | Formats pre-filled report_draft - findings already written by exploit/zerodayhunt |

### Specialized Attack Modules

| Skill | Technique Files | What It Does |
|---|---|---|
| `/redteam` | 14 | Initial access, lateral movement, AD exploitation, C2 frameworks, persistence, cloud APT, exfil, OPSEC |
| `/403-bypass` | - | 29+ techniques: header tricks, parser confusion, Orange Tsai `?` ACL bypass (BH2024), CVE-2025-32094 |
| `/oauth-attacks` | - | Redirect URI bypass, CSRF, PKCE downgrade, JWT confusion chains |
| `/race-conditions` | - | HTTP/2 single-packet attack, coupon reuse, double-spend, OTP bypass |
| `/cloud-audit` | - | AWS SSRF->IAM, S3 enum, GCP, Azure, K8s unauthenticated API |
| `/ctf` | - | HackTheBox/TryHackMe - web/crypto/pwn/RE/forensics/OSINT/stego - fully isolated |
| `/compact` | - | Compresses session.json when context grows large mid-engagement |

### Technique Coverage Highlights

| Technique | File | Reference |
|---|---|---|
| SSRF + Blind OOB chain | `ssrf-oob.md` | Phase 8, 32 |
| JWT RS256->HS256 confusion | `jwt-saml-sso.md` | Phase 7, 31 |
| Prototype pollution -> EJS RCE | `client-proto.md` | USENIX 2023 |
| mXSS DOMPurify bypass | `client-proto.md` | CVE-2024-47875 |
| PDF generator SSRF -> AWS IAM | `file-crypto.md` | Phase 26 |
| ECDSA nonce reuse + Psychic Signatures | `file-crypto.md` | CVE-2022-21449 |
| Chain blueprints A-K | `chain-blueprints.md` | Phase 23 |
| ImageMagick arbitrary file read | `file-crypto.md` | CVE-2022-44268 |
| CI/CD pull_request_target RCE | `cicd.md` | Phase 16 |
| XS-Leaks cache probing | `xs-leaks.md` | DEF CON 29 |
| HTTP Desync CL.0 + H2.CL | `admin-infra.md` | Black Hat 2022 |
| Nginx alias off-by-slash traversal | `admin-infra.md` | Phase 28 |

---

## Proof It Works

Real anonymized findings made with Akira. Details shared privately per responsible disclosure.

| # | Type | Severity | Bounty | Skill Chain |
|---|---|---|---|---|
| 1 | SSRF -> AWS IAM Credential Extraction | Critical | $2,500 | `/recon` -> `/exploit` -> `/cloud-audit` |
| 2 | OAuth Open Redirect -> Auth Code Interception | Critical | $1,800 | `/recon` -> `/oauth-attacks` |
| 3 | Race Condition: Coupon Applied 7x | High | $800 | `/race-conditions` |
| 4 | Strapi SSRF Bypass + MIME Fail-Open (CVE filed) | Critical | - | `/zerodayhunt` |
| 5 | JWT RS256->HS256 Confusion -> Admin Access | Critical | $1,500 | `/zerodayhunt` |

---

## Why Not PentestGPT?

| Capability | PentestGPT | HexStrike | **Akira** |
|---|:---:|:---:|:---:|
| Full 6-phase engagement lifecycle | Partial | - | **YES** |
| Phase artifact handoffs (session.json) | - | - | **YES** |
| Anti-hallucination evidence gate | - | - | **YES** |
| Confidence scoring per finding (0-100) | - | - | **YES** |
| Attack graph engine (dynamic fork scheduling) | - | - | **YES** |
| Hypothesis engine (ranked chains, real-time calibration) | - | - | **YES** |
| Signal bus + cross-skill correlation | - | - | **YES** |
| **Thin router + technique library (75% token reduction)** | - | - | **YES** |
| **Unified Phase 0 (intel relay across all skills)** | - | - | **YES** |
| Red team full chain (initial access -> exfil -> OPSEC) | - | Partial | **YES** |
| AD full chain (BloodHound -> DCSync -> ADCS ESC1-8) | - | Partial | **YES** |
| 403 bypass (29+ techniques, conference-grade 2024-2026) | - | - | **YES** |
| OAuth/OIDC exploitation suite | - | - | **YES** |
| Race conditions (single-packet attack) | - | - | **YES** |
| Cloud audit (AWS + GCP + Azure + K8s) | - | Partial | **YES** |
| CTF mode (HackTheBox, TryHackMe) | **YES** | - | **YES** |
| Native in Claude Code, Gemini, Cursor | Partial | - | **YES** |
| Free + MIT | **YES** | Partial | **YES** |

---

## Roadmap

| Release | Status | Highlights |
|---|---|---|
| **Hydra v1.0.0** | Shipped | 12 core skills, 6-phase lifecycle |
| **Hydra v1.0.1** | Shipped | `403-bypass` + recon 23-step upgrade |
| **Hydra v1.0.2** | Shipped | Attack Graph Engine - hypothesis engine, signal bus, fork scheduler |
| **Basilisk v1.1.0** | Dev branch | Thin router + technique library, 68 technique files, `/redteam`, unified Phase 0, race-proof signals |
| Raven v1.2.0 | Month 2 | Akira Context Engine, `cache-attacks`, `csp-bypass`, `graphql` standalone skill |
| Phantom v1.3.0 | Month 3 | `mobile` deep-dive, `burp-integration`, WASM analysis automation |
| Leviathan v2.0.0 | Month 6 | Akira Brain - autonomous multi-skill orchestration, `postmap-recon` |

---

## Contributing

Found a technique that belongs in Akira? Fix a skill bug? Submit a real finding?

Each technique file in `tech/` is ~80 lines and self-contained - adding a new attack vector is now a single file PR instead of editing a 1800-line monolith.

See [CONTRIBUTING.md](CONTRIBUTING.md) - PRs welcome, fast review.

---

## Legal

For **authorized security testing only** - bug bounty programs, systems you own, CTF competitions.

Unauthorized testing is illegal. Authors not responsible for misuse.

---

<div align="center">

Built for bug hunters, by bug hunters.

**[Star this repo](https://github.com/kalpmodi/akira) to stay updated when new skills ship.**

</div>
