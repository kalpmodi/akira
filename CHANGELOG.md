# Changelog

All notable changes to Akira will be documented here.

---

## [1.0.0] - 2026-04-16

### Added - Core 7-Phase Engagement Lifecycle
- `plan-engagement` - scope, PTT generation, session.json initialization
- `recon` - subdomains, live hosts, ports, URLs, tech stack fingerprint
- `secrets` - API keys, tokens, credentials in JS/source/git/Postman collections
- `exploit` - XSS (dalfox), SQLi (sqlmap), nuclei, deserialization, SSTI, XXE, NoSQLi, WebSocket
- `zerodayhunt` - chain attacks, JWT confusion, SSRF->IAM, WAF bypass, type juggling, prototype pollution
- `triage` - severity clustering, confidence scoring (0-100), FP verification gate, deduplication
- `report` - pentest report + HackerOne/Bugcrowd submission format

### Added - Specialized Attack Modules (Month 1)
- `ad-attacks` - BloodHound path analysis, Kerberoasting, AS-REP roasting, DCSync, Pass-the-Hash,
  Pass-the-Ticket, ADCS ESC1-8, unconstrained/constrained delegation, Golden/Silver Ticket
- `oauth-attacks` - redirect URI bypass, CSRF, PKCE downgrade, JWT confusion, implicit flow token theft,
  postMessage leakage, authorization code interception chains
- `race-conditions` - HTTP/2 single-packet attack, coupon reuse, wallet double-spend, OTP bypass, TOCTOU
- `cloud-audit` - AWS SSRF->IAM, S3 enum, IAM privesc (Pacu), GCP service account, Azure RBAC,
  K8s API unauthenticated access, etcd exposure, kubelet API
- `ctf` - HackTheBox/TryHackMe methodology, web/crypto/pwn/RE/forensics/OSINT/stego

### Added - Architecture
- Phase handoff system: each skill reads `interesting_<phase>.md` from previous phases
- `session.json` cross-phase intelligence tracking (live hosts, credentials, PTT, tech stack)
- Anti-hallucination evidence gate enforced in every skill
- Confidence scoring system (0-100) with auto-downgrade below 70
- False positive verification gate in triage
- Pentest Task Tree (PTT) living attack graph in session.json

### Added - Platform Support
- Claude Code native (primary) via `~/.claude/skills/`
- Gemini CLI adapter (`GEMINI.md`)
- Cursor rules (`.cursor/rules/akira.mdc`)
- Codex/AGENTS.md pattern
- Generic agent support via `AGENTS.md`

### Added - Toolchain
- `install.sh` - one-command skill installer
- `bootstrap.sh` - installs nuclei, dalfox, subfinder, httpx, dnsx, ffuf, sqlmap, nmap, trufflehog
- `FINDINGS.md` - live bug bounty findings (updated weekly)

---

## Upcoming

### [1.1.0] - Month 2 (May 2026)
- `graphql` - introspection abuse, batching, field-level authz bypass
- `deserialization` - ysoserial, PHPGGC, pickle chains
- `prototype-pollution` - Node.js client + server RCE chains
- `supply-chain` - dependency confusion, typosquatting, namespace squatting
- `ci-cd-audit` - 9 GitHub Actions attack vectors

### [1.2.0] - Month 3 (June 2026)
- Akira Context Engine - auto CVE lookup for detected stack + HackerOne public reports
- `cache-attacks` - poisoning + deception unified playbook
- `csp-bypass` - JSONP, nonce reuse, base-URI injection

### [1.3.0] - Month 4 (July 2026)
- `mobile` - Android APK, Firebase, iOS, Frida certificate pinning bypass
- `burp-integration` - native Burp MCP tools (Repeater, Intruder, proxy history)

### [2.0.0] - Month 6 (September 2026)
- Akira Brain - persistent attack tree across sessions
- `postmap-recon` - PostmapDB integration (leaked Postman collections -> live secrets)
- `red-team` - MITRE ATT&CK full emulation
