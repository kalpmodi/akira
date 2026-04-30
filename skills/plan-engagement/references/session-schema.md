# session.json — Full Field Reference

Every skill in the Akira chain reads and writes to this file.
Location: `~/pentest-toolkit/results/<target>/session.json`

---

## Top-level fields

| Field | Type | Written by | Read by | Description |
|---|---|---|---|---|
| `target` | string | plan-engagement | all skills | Primary target domain or IP |
| `started` | string | plan-engagement | report | ISO date engagement began |
| `program` | object | plan-engagement | report, triage | Program context |
| `engagement_state` | string | all skills | all skills | Current state machine mode |
| `fork_budget` | object | plan-engagement, all skills | all skills | Fork concurrency control |
| `active_chain` | array | plan-engagement | all skills | Ordered list of active phases |
| `flagged_modules` | array | plan-engagement, recon | all skills | Optional modules to activate |
| `hypotheses` | array | plan-engagement, all skills | all skills | Ranked attack chain predictions |
| `signals` | array | all skills | all skills | Live intelligence event stream |
| `threads` | array | all skills | all skills | Active and fork thread registry |
| `discovery_queue` | array | all skills | plan-engagement, user | Pending surfaces awaiting fork budget |
| `tested_surfaces` | array | all skills | all skills | Deduplication log |
| `ptt` | object | all skills | report, triage | Pentest task tree graph |
| `intel` | object | recon, secrets, exploit | all exploit skills | Extracted intelligence |
| `report_draft` | object | all skills | report | Pre-filled findings as discovered |

---

## program

```json
"program": {
  "type": "bug_bounty | pentest | ctf | lab",
  "platform": "hackerone | bugcrowd | intigriti | unknown",
  "name": "Program display name or null"
}
```

Report skill uses `type` to determine output format. `platform` determines submission template.

---

## engagement_state

Valid values: `"WIDE"` `"DEEP"` `"HARVEST"` `"WRAP"`

- `WIDE` — exploring broadly, all forks shallow, maximizing signals
- `DEEP` — concentrated on one confirmed hypothesis chain, full depth
- `HARVEST` — extracting evidence for a confirmed critical chain
- `WRAP` — engagement complete, consolidating, no new forks

**Every skill must read this field before deciding what to do.**
In DEEP state, skip new surface forks — queue them. In HARVEST, do not fork anything.

---

## fork_budget

```json
"fork_budget": {
  "max": 3,
  "active": 1,
  "queued": 0
}
```

Before spawning a fork: check `active < max`. If not: push to `discovery_queue`.
After spawning: increment `active`. After fork terminates: decrement `active`, process next from queue.

---

## hypotheses[]

```json
{
  "id": "H1",
  "label": "SSRF → AWS IAM credential extraction",
  "probability": 0.82,
  "status": "active | confirmed | denied",
  "evidence_required": "SSRF injection point + metadata endpoint reachable",
  "boosted_by": ["SSRF_VECTOR", "TECH_DETECTED"],
  "supporting_signals": ["sig-001", "sig-003"],
  "denying_signals": []
}
```

**Calibration protocol** — run after every new signal:
1. If signal type is in `boosted_by` → +8-12% probability
2. If signal value directly matches `evidence_required` → +15-25%
3. If signal contradicts the chain → -25-35%
4. If probability drops to 0-15% → set `status: "denied"`, log attack path to `tested_surfaces`
5. If probability reaches 85%+ → set `engagement_state: "DEEP"`, concentrate resources
6. If confirmed → set `status: "confirmed"`, write to `report_draft.findings[]`

Do not remove denied hypotheses — they are the dedup anchor.

---

## signals[]

```json
{
  "id": "sig-001",
  "type": "SURFACE_FOUND",
  "value": "internal.target.com:8080",
  "confidence": 91,
  "emitted_by": "main/exploit",
  "timestamp": "2026-04-21 14:32",
  "consumed_by": ["fork-1"],
  "triggered": "fork:/recon on internal.target.com:8080"
}
```

Signal types and what emits them:

| Type | Emitted by | Meaning |
|---|---|---|
| `SURFACE_FOUND` | recon, exploit, zerodayhunt | New host, subdomain, IP, or endpoint |
| `CRED_FOUND` | secrets, exploit | Credential, API key, session token, secret |
| `TECH_DETECTED` | recon, secrets | Framework, language, cloud provider, service |
| `WAF_CONFIRMED` | recon, 403-bypass | WAF or CDN identified with fingerprint |
| `INTERNAL_IP` | exploit, cloud-audit | Private network IP from SSRF or redirect |
| `JWT_FOUND` | recon, secrets, exploit | JWT token in response |
| `SSRF_VECTOR` | exploit, zerodayhunt | Confirmed SSRF injection point |
| `AUTH_BYPASS` | exploit, 403-bypass, oauth-attacks | Auth control bypassed with HTTP proof |
| `VULN_CONFIRMED` | exploit, zerodayhunt, all | Exploitable vuln with reproducible proof |

After emitting a signal, check correlation rules in `plan-engagement/SKILL.md` Step 6 and act.

---

## threads[]

```json
{
  "id": "main | fork-N",
  "target": "target being attacked",
  "phase": "current phase name",
  "status": "active | running | low_yield | terminated | done",
  "parent": "null for main, parent thread ID for forks",
  "genealogy": ["main", "fork-1"],
  "trigger": "signal ID or description that spawned this fork",
  "health": {
    "steps_since_signal": 0,
    "status": "healthy | low_yield"
  }
}
```

**Health check protocol:**
- Increment `steps_since_signal` each step a thread takes without emitting a signal
- At 5+ → set `health.status: "low_yield"`
- At 8+ → terminate thread, reclaim fork budget slot, log to `tested_surfaces`
- Reset counter to 0 whenever a signal is emitted

---

## discovery_queue[]

```json
{
  "id": "dq-001",
  "surface": "new-bundle.abc123.js",
  "type": "js_bundle | host | endpoint | credential",
  "action": "/secrets",
  "confidence": 67,
  "priority": 84,
  "queued_by": "main",
  "queued_at": "2026-04-21 14:45",
  "hypothesis": "H4"
}
```

Priority score: `(impact_score × confidence) / estimated_token_cost`

When a fork slot opens, pop the highest priority item and spawn the fork.

---

## tested_surfaces[]

```json
{
  "surface": "api.target.com/admin",
  "action": "exploit:jwt_confusion",
  "result": "RS256 not in use — skipped",
  "thread": "fork-1",
  "timestamp": "2026-04-21 14:32"
}
```

**Check this before every action.** If `surface + action` already exists → skip without retry.
This is the deduplication layer. Write to it after every completed action, successful or not.

---

## ptt.graph[]

```json
{
  "id": "main",
  "label": "api.target.com",
  "children": ["fork-1", "fork-2"],
  "status": "active | done | terminated",
  "trigger": null,
  "phase": "exploit"
}
```

Graph grows as forks are spawned. Report skill reads this to reconstruct attack lineage.

---

## intel{}

```json
"intel": {
  "live_hosts": ["api.target.com", "internal.target.com:8080"],
  "subdomains": ["api", "auth", "admin", "staging"],
  "open_ports": {"api.target.com": [80, 443, 8080]},
  "technologies": ["nginx/1.25", "Django/4.2", "AWS S3", "Redis"],
  "waf": "Cloudflare",
  "internal_ips": ["10.0.1.45", "172.16.0.12"],
  "credentials": [
    {"type": "aws_key", "value": "AKIA...", "source": "main.js line 847", "tested": false}
  ],
  "endpoints": ["/api/upload", "/oauth/authorize", "/admin/users"],
  "jwt_tokens": ["eyJhbGc..."],
  "api_keys": ["sk-..."],
  "cookies": ["session=...; HttpOnly; Secure"]
}
```

All skills read from `intel` before acting — no need to rediscover what's already known.
All skills write new intel here as they discover it.

---

## report_draft{}

`report_draft.findings[]` uses the **Canonical Scalpel Finding Record** format.
Write the full record the moment a hypothesis is confirmed. `triage` will run the Precision Gate and assign the SCL ID. `/report` reads this and formats — it does not discover, only presents.

```json
"report_draft": {
  "findings": [
    {
      "scl_id": null,
      "title": "SSRF -> AWS IAM Credential Extraction",
      "date": "2026-04-21",
      "severity": "Critical",
      "confidence": 96,
      "status": "confirmed",

      "dna": {
        "hash": null,
        "vuln_class": "ssrf_aws_imds_iam",
        "tech_fingerprint": ["aws", "nginx"],
        "chain_fingerprint": "proxy_endpoint->imdsv1->iam_creds->s3_access"
      },

      "kccg": {
        "score": null,
        "initial_access": {"pass": true, "proof": "GET /api/proxy?url=http://169.254.169.254/"},
        "escalation": {"pass": true, "proof": "IAM role ec2-prod-role credentials extracted"},
        "data_access": {"pass": true, "proof": "s3://prod-db-backups listed"},
        "reproducible": {"pass": true, "proof": "3/3 replays identical"},
        "scope_valid": {"pass": true, "proof": "api.target.com in program scope"},
        "severity_cap": null
      },

      "precision_gate": {
        "authenticity": null,
        "reproducibility": null,
        "data_sensitivity": null,
        "scope_validity": null,
        "kccg_threshold": null,
        "status": null,
        "failed_layers": []
      },

      "kill_chain": [
        {
          "step": 1,
          "technique": "SSRF injection via proxy endpoint",
          "action": "GET /api/proxy?url=http://169.254.169.254/latest/meta-data/",
          "response_fragment": "ami-id, instance-id, iam/",
          "signal": "SSRF_VECTOR"
        },
        {
          "step": 2,
          "technique": "IMDSv1 credential extraction",
          "action": "GET /api/proxy?url=.../iam/security-credentials/ec2-prod-role",
          "response_fragment": "AccessKeyId: ASIAZ...",
          "signal": "CRED_FOUND"
        },
        {
          "step": 3,
          "technique": "Credential verification and data access",
          "action": "aws sts get-caller-identity && aws s3 ls",
          "response_fragment": "prod-db-backups accessible",
          "signal": "VULN_CONFIRMED"
        }
      ],

      "evidence": {
        "http_proof": "http-responses/ssrf-iam-chain.txt",
        "supporting_signals": ["sig-003", "sig-007"],
        "pocs_dir": "pocs/"
      },

      "impact": {
        "description": "Full AWS account access, production database backups exposed",
        "cvss_estimate": 9.8
      },

      "engagement": {
        "hypothesis": "H1",
        "skills_chain": ["recon", "exploit", "cloud-audit"],
        "signals_path": ["SSRF_VECTOR", "CRED_FOUND", "VULN_CONFIRMED"]
      },

      "confirmed_at": "2026-04-21 15:12"
    }
  ],
  "last_updated": "2026-04-21 15:12"
}
```

**Field fill rules:**
- `scl_id`: filled by `/triage` after Precision Gate passes
- `dna.hash`: filled by `/triage` using sha256(vuln_class+tech_fingerprint+chain_fingerprint)
- `kccg.score` and `kccg.severity_cap`: computed by `/triage`
- `precision_gate.*`: all layers evaluated by `/triage`
- `kill_chain[]`: fill step-by-step as the chain is proven during exploitation
- Everything else: fill immediately when the finding is confirmed

---

## scalpel{}

Top-level engagement precision tracking block. Written by `plan-engagement` on init, updated by all skills.

```json
"scalpel": {
  "id_counter": 6,
  "snr": {
    "tool_runs": 0,
    "signals_emitted": 0,
    "signals_confirmed": 0,
    "false_positives": 0,
    "yield_rate": null,
    "conversion_rate": null,
    "noise_penalty": null,
    "scalpel_score": null
  },
  "doom_loop": {
    "technique_runs": {},
    "flagged_techniques": []
  }
}
```

**SNR formula:**
```
yield_rate       = signals_emitted / tool_runs
conversion_rate  = signals_confirmed / signals_emitted
noise_penalty    = false_positives / (signals_confirmed + false_positives)
scalpel_score    = round((conversion_rate * 100) * (1 - noise_penalty))
```

**Doom loop detection:**
- `technique_runs` tracks `{"surface:technique": count}` for every action
- If any entry exceeds 3 on the same surface -> add to `flagged_techniques`
- Skills must check `flagged_techniques` before running - skip flagged combinations
- Reset count when surface is confirmed or denied

**Scalpel score interpretation:**
- 80-100: Surgical - excellent hypothesis quality, low noise
- 60-79: Precise - good signal discipline, minor noise
- 40-59: Noisy - technique breadth too wide, tighten hypotheses
- Below 40: Undisciplined - methodology needs review

`id_counter` starts at next available SCL number. Read by `triage` to assign SCL IDs.
After assigning `N` findings in a session, increment by N and write back to `~/.akira/memory.json`.
