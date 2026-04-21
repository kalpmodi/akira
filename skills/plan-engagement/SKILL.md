---
name: plan-engagement
description: Use when starting any pentesting engagement, receiving a target domain or IP, saying "new engagement", "start a pentest", "plan this target", or beginning any offensive security assessment. Invoke this FIRST before any other skill. Also triggers on "bug bounty on X", "test X for me", "attack X", "scope is X".
---

# Plan Engagement — Attack Graph Engine

## Philosophy

You are not filling out a form. You are an attack planner initializing a live intelligence system.

Extract everything from the user's message. Ask at most one question — only if the target itself is completely missing. Everything else has smart defaults. Your job is to generate a dynamic attack graph, not a static checklist, and hand the user a running start.

---

## Step 1: Infer From the Message

Extract without asking:

| Extract | Source | Default if missing |
|---|---|---|
| Target | domain, IP, URL, app name in message | ask — only this |
| Program type | "bug bounty", "pentest", "CTF", "my lab" | bug_bounty |
| Platform | "HackerOne", "Bugcrowd", "Intigriti" | unknown |
| Tech hints | AWS, OAuth, GraphQL, checkout, LDAP | none |
| Constraint hints | "no active scan", "stealth", "out of scope" | none |
| Attack surface hints | "403s", "login page", "API", "internal" | none |

If the user says "api.stripe.com, found some 403s, AWS-backed" — you have target, hints for 403-bypass and cloud-audit, no questions needed.

---

## Step 2: Generate Hypotheses

Generate 4-6 ranked hypotheses — probabilistic attack chains grounded in what you know. These are not guesses; they are structured predictions that drive the entire engagement.

```
H1 [82%]  SSRF → AWS IAM credential extraction
          Evidence required: SSRF injection point + metadata endpoint reachable
          Boosted by signals: SSRF_VECTOR, TECH_DETECTED(AWS), INTERNAL_IP

H2 [71%]  OAuth open redirect → authorization code interception
          Evidence required: /oauth/authorize + redirect_uri param present
          Boosted by signals: JWT_FOUND, TECH_DETECTED(OAuth/SSO)

H3 [54%]  Race condition on checkout flow
          Evidence required: cart/coupon/transfer endpoint + timing gap
          Boosted by signals: SURFACE_FOUND(checkout), TECH_DETECTED(payments)

H4 [38%]  JWT RS256 → HS256 algorithm confusion
          Evidence required: JWT in responses + /jwks.json accessible
          Boosted by signals: JWT_FOUND, SURFACE_FOUND(jwks)
```

**Calibration rules** — update after every incoming signal:
- Signal matches `evidence_required` → +15-25% (specificity determines how much)
- Signal matches `boosted_by` list → +8-12%
- Signal directly contradicts hypothesis → -25-35%
- Hypothesis hits 0-15% → mark DENIED, log to `tested_surfaces`, never retest
- Hypothesis hits 85%+ → immediately transition engagement to DEEP state
- Hypothesis hits CONFIRMED → write finding to `report_draft.findings[]`, continue

---

## Step 3: Auto-Activate Modules

Core chain always active: `recon → secrets → exploit → triage → report`

Auto-flag additional modules based on extracted signals and hints:

| Signal / keyword detected | Module flagged |
|---|---|
| AWS / S3 / Lambda / IAM / GCP / Azure / cloud | `cloud-audit` |
| 403 / forbidden / blocked / WAF hint | `403-bypass` |
| OAuth / SSO / OIDC / JWT / login | `oauth-attacks` |
| checkout / cart / coupon / wallet / transfer / balance | `race-conditions` |
| AD / LDAP / Kerberos / domain controller / corporate | `ad-attacks` |
| GraphQL / introspection | `zerodayhunt` (GraphQL focus) |
| HackTheBox / TryHackMe / CTF / flag | `ctf` |

Flagged modules activate when the main chain reaches Phase 3 or a relevant signal confirms them.

---

## Step 4: Initialize session.json

Create `~/pentest-toolkit/results/<target>/`:

```bash
mkdir -p ~/pentest-toolkit/results/<target>/{screenshots,http-responses,loot}
```

Write `session.json` — lean init, only populate what is actually known:

```json
{
  "target": "<target>",
  "started": "<YYYY-MM-DD>",
  "program": {
    "type": "bug_bounty",
    "platform": "unknown",
    "name": null
  },
  "engagement_state": "WIDE",
  "fork_budget": {
    "max": 3,
    "active": 0,
    "queued": 0
  },
  "active_chain": ["recon", "secrets", "exploit", "triage", "report"],
  "flagged_modules": [],
  "hypotheses": [
    {
      "id": "H1",
      "label": "<attack chain name>",
      "probability": 0.82,
      "status": "active",
      "evidence_required": "<what confirms this>",
      "boosted_by": ["SIGNAL_TYPE"],
      "supporting_signals": [],
      "denying_signals": []
    }
  ],
  "signals": [],
  "threads": [
    {
      "id": "main",
      "target": "<target>",
      "phase": "plan",
      "status": "active",
      "parent": null,
      "genealogy": [],
      "health": {"steps_since_signal": 0, "status": "healthy"}
    }
  ],
  "discovery_queue": [],
  "tested_surfaces": [],
  "ptt": {
    "graph": [
      {"id": "root", "label": "<target>", "children": ["main"], "status": "active"}
    ]
  },
  "intel": {
    "live_hosts": [],
    "subdomains": [],
    "open_ports": {},
    "technologies": [],
    "waf": null,
    "internal_ips": [],
    "credentials": [],
    "endpoints": [],
    "jwt_tokens": [],
    "api_keys": [],
    "cookies": []
  },
  "report_draft": {
    "findings": [],
    "last_updated": null
  }
}
```

Only write fields you have actual values for. Leave everything else as shown — phases will populate as the engagement runs.

See `references/session-schema.md` for full field definitions.

---

## Step 5: The Engagement State Machine

The engagement always runs in one of four modes. You decide when to transition — not a timer, not a checklist. Transition when the intelligence justifies it.

### WIDE (start here)
Goals: maximize surface coverage, emit signals, calibrate hypotheses rapidly.
- Forks are shallow — single targeted checks, not full phase runs
- Fork all medium+ confidence discoveries (>40%)
- Hypotheses update constantly
- **Transition to DEEP** when any hypothesis exceeds 85% confidence

### DEEP (one confirmed hypothesis, drilling it)
Goals: prove the full attack chain — credentials extracted, data accessed, or RCE demonstrated.
- All fork budget concentrated on the confirmed chain
- New discoveries written to `discovery_queue`, not forked yet
- If chain dead-ends after 3 serious attempts → back to WIDE
- **Transition to HARVEST** when full chain is proven with evidence

### HARVEST (critical chain confirmed with proof)
Goals: extract maximum evidence, nothing else.
- Capture raw HTTP requests/responses, screenshots, extracted data into `loot/`
- Write confirmed finding to `report_draft.findings[]` immediately with full chain
- Zero new forks — evidence collection only
- **Transition back to WIDE** once evidence is captured and documented

### WRAP (no new signals across all threads for 5+ steps)
Goals: close the engagement cleanly.
- Drop fork budget to 0
- Drain `discovery_queue` — assess each item, act or discard
- Consolidate signals into any remaining findings
- Notify: "Engagement ready. Run /triage then /report."

---

## Step 6: Signal Protocol

Every skill in the chain emits signals when discoveries are made. Signals are the nervous system of the engagement — they drive hypothesis calibration, fork decisions, and state transitions.

**Emit a signal for every meaningful discovery. Never just log something locally.**

Signal format in `session.json`:
```json
{
  "id": "sig-NNN",
  "type": "SURFACE_FOUND",
  "value": "internal.target.com:8080",
  "confidence": 91,
  "emitted_by": "main/exploit",
  "timestamp": "YYYY-MM-DD HH:MM",
  "consumed_by": [],
  "triggered": null
}
```

Signal types:
- `SURFACE_FOUND` — new host, subdomain, IP range, internal endpoint
- `CRED_FOUND` — password, API key, token, secret
- `TECH_DETECTED` — framework, language, cloud provider, service
- `WAF_CONFIRMED` — WAF or CDN identified and fingerprinted
- `INTERNAL_IP` — private network address discovered via SSRF/redirect
- `JWT_FOUND` — JWT token present in response headers or body
- `SSRF_VECTOR` — confirmed SSRF injection point with outbound connectivity
- `AUTH_BYPASS` — authentication control bypassed with proof
- `VULN_CONFIRMED` — exploitable vulnerability with reproducible proof

### Signal Correlation Rules

After every new signal arrives, check these patterns. When a pattern matches — act immediately, don't wait for the next phase:

| Pattern | Emergent action |
|---|---|
| `SSRF_VECTOR` + `TECH_DETECTED(AWS/GCP/Azure)` | Upgrade cloud-audit hypothesis to 95%, full fork immediately |
| `WAF_CONFIRMED` + new `SURFACE_FOUND` | Flag 403-bypass for the new surface too |
| `CRED_FOUND` + 2+ `SURFACE_FOUND` | Credential spray fork on all discovered surfaces |
| `JWT_FOUND` + `TECH_DETECTED(node/python/java)` | Spawn JWT confusion test, activate oauth-attacks |
| `INTERNAL_IP` + `SSRF_VECTOR` | Transition to DEEP state, concentrate all budget on this chain |
| 3+ `VULN_CONFIRMED` | Transition to HARVEST state |
| `TECH_DETECTED` signal | Push tech to all active thread contexts immediately |

These are patterns to recognize, not exhaustive rules. Use judgment — if a combination of signals tells a story, act on the story.

### Tech Stack Propagation

When `TECH_DETECTED` fires, immediately inform all active threads:

```
TECH_DETECTED: Django
→ exploit threads: deprioritize SQLi (ORM likely), prioritize SSTI
→ secrets threads: look for SECRET_KEY, DEBUG=True in source
→ zerodayhunt: test /?debug=true, admin/

TECH_DETECTED: Redis
→ exploit: add localhost:6379 to SSRF target list
→ cloud-audit: check for unauthenticated access

TECH_DETECTED: AWS
→ activate cloud-audit module
→ add 169.254.169.254 to SSRF target list
→ boost H1 by +15%
```

---

## Step 7: Fork Protocol

See `references/fork-protocol.md` for the full protocol used by all skills.

### When to fork
- `SURFACE_FOUND` with confidence > 40%
- Hypothesis calibration pushes a chain above 70%
- `CRED_FOUND` with a new untested attack surface

### Confidence tiers
| Confidence | Fork action |
|---|---|
| < 40% | Write to `discovery_queue`, notify user, no auto-fork |
| 40-70% | Shallow fork — one targeted check, emit signal back |
| > 70% | Full fork — run complete phase on new surface |

### Fork priority when budget is full
```
priority = (impact_score × confidence) / estimated_token_cost
```
Highest score gets the next available slot. User sees: "2 forks active, 1 queued (score: 84, surface: internal.target.com)."

### Fork brief — keep under 80 tokens
```
FORK: fork-<N>
Target: <new surface>
Phase: <recon|secrets|exploit>
Trigger: <signal ID and value that caused this>
Hypothesis: <H-id being tested>
Known intel: tech=[...], creds=[...], waf=<value>
Write back: session.json signals[] + threads[fork-<N>]
Dedup: check tested_surfaces[] before every action
Emit signals for every discovery. No narration.
```

### Dead-end detection
- Fork emits 0 signals for 5+ consecutive steps → mark `health.status: low_yield`
- Persists for 3 more steps → terminate fork, reclaim slot
- Before terminating: log all attempted paths to `tested_surfaces[]`
- Notify main thread: slot reclaimed, next item in priority queue activates

---

## Step 8: Deduplication

Before any action — main thread or any fork:
1. Check `tested_surfaces[]` for this exact target + action combination
2. If found → skip it, move to the next action without retrying
3. If not found → proceed, then append to `tested_surfaces[]` on completion

```json
{
  "surface": "api.target.com/admin",
  "action": "exploit:jwt_confusion",
  "result": "RS256 not in use — DENIED",
  "thread": "fork-1",
  "timestamp": "2026-04-21 14:32"
}
```

This prevents two forks from independently running the same test. It also prevents revisiting dead ends across sessions.

---

## Step 9: Live Report Draft

Do not wait for /report to document findings. Build the draft as the engagement runs.

When any hypothesis reaches CONFIRMED or any VULN_CONFIRMED signal fires:
1. Write finding immediately to `report_draft.findings[]`
2. Include: attack chain, all supporting signal IDs, HTTP evidence references, severity rationale
3. Mark hypothesis `status: "confirmed"` in session.json
4. Continue the engagement — do not stop to write prose

When /report is eventually called, 80-90% of the content is pre-filled. The report skill reviews, completes the narrative, and formats for HackerOne/Bugcrowd/pentest report.

---

## Step 10: Output

Output exactly this — nothing more. No headers, no filler, no explanations unless asked:

```
Target: <target>  |  Type: <inferred: API/Web/Cloud/AD>  |  Program: <type> (<platform>)
Fork budget: 3  |  State: WIDE

Hypotheses:
  H1 [82%]  <label>
  H2 [71%]  <label>
  H3 [54%]  <label>
  H4 [38%]  <label>

Chain: recon → secrets → exploit → triage → report
Flagged: <modules or "none yet">

session.json initialized. Evidence dirs created.
/recon <target>
```

Generate `plan.md` only if the user explicitly says "full plan", "generate a doc", or "I want a written plan."

Total response: under 20 lines. The engagement is live. Let the graph build itself.

---

## Reference files

- `references/session-schema.md` — every session.json field defined, what writes it, what reads it
- `references/fork-protocol.md` — full signal emission and fork briefing protocol for all skills
