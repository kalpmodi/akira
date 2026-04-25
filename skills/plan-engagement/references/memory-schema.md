# ~/.akira/memory.json — Cross-Engagement Intelligence Memory

Persists across all engagements. Read by `plan-engagement` to seed hypotheses.
Written by `triage` at engagement close.

Location: `~/.akira/memory.json`

---

## Purpose

Akira learns from every engagement and gets more precise over time:
- Hypothesis priors improve from real confirmed chains (not hardcoded)
- Techniques with low confirmation rates get flagged to reduce noise
- WAF bypass strategies accumulate from real bypass events
- Program-specific patterns inform reporting decisions

Anti-overfitting rules are built in:
- Prior probability cap: 0.85 (memory alone cannot create a certainty)
- Bayesian decay: old data weight reduces over time
- Minimum sample threshold: 3 confirmations before a prior exceeds 0.75
- Novelty bonus: untried techniques get a baseline 0.40 prior regardless of memory

---

## Schema

```json
{
  "version": "1.0",
  "last_updated": "2026-04-24",
  "scl_id_counter": 6,

  "tech_vuln_priors": {
    "<tech_key>": {
      "chain": "<vuln_class>",
      "prior_probability": 0.78,
      "confirmed_count": 1,
      "denied_count": 0,
      "last_seen": "2026-01-15",
      "avg_kccg": 1.0,
      "decay_weight": 1.0
    }
  },

  "atw": {
    "<technique_id>": {
      "attempts": 5,
      "confirmations": 3,
      "denials": 2,
      "confirmation_rate": 0.60,
      "trust_level": "medium",
      "last_updated": "2026-04-24"
    }
  },

  "hallucination_guard": {
    "<technique_id>": {
      "claimed": 4,
      "confirmed": 1,
      "hallucination_rate": 0.75,
      "flagged": true,
      "flag_reason": "High claim rate relative to confirmations"
    }
  },

  "waf_bypass_priors": {
    "<waf_name>": {
      "effective_techniques": ["<technique>"],
      "ineffective_techniques": ["<technique>"],
      "avg_bypass_steps": 8,
      "last_updated": "2026-04-24"
    }
  },

  "program_patterns": {
    "<platform>": {
      "preferred_severity_threshold": "high",
      "duplicate_rate": "medium",
      "avg_response_time_days": 5,
      "tips": []
    }
  },

  "dna_registry": [
    {
      "hash": "sha256:...",
      "vuln_class": "<class>",
      "tech_fingerprint": ["<tech>"],
      "chain_fingerprint": "<chain>",
      "scl_id": "SCL-2026-001",
      "confirmed_count": 1,
      "avg_confidence": 96
    }
  ],

  "snr_history": {
    "all_time_avg_scalpel_score": 84,
    "best_score": 91,
    "worst_score": 62,
    "total_engagements": 5,
    "total_certified_findings": 5,
    "total_false_positives": 0
  }
}
```

---

## tech_vuln_priors

Keys use format: `"<primary_tech>+<secondary_tech>"` (lowercase, sorted alphabetically).

Examples:
- `"aws+ssrf"` -> `ssrf_aws_imds_iam` chain
- `"jwt+rs256"` -> `jwt_rs256_hs256_confusion` chain
- `"strapi+node.js"` -> `strapi_ssrf_bypass` chain

**Bayesian update formula (run after each engagement close):**
```
new_prior = (old_prior * decay_weight * confirmed_count + new_evidence) /
            (confirmed_count + denied_count + 1)

decay_weight = max(0.7, 1.0 - (days_since_last_seen / 365) * 0.3)
```

**Anti-overfitting caps:**
- `prior_probability` hard cap: 0.85 (cannot reach certainty from memory alone)
- Minimum confirmations for prior > 0.75: 3
- New tech combination (never seen): default prior 0.40

**How `plan-engagement` uses this:**
```bash
# Read tech hints extracted from user message
TECH=$(extracted_tech_hints)

# Look up matching keys in tech_vuln_priors
# For each match: boost hypothesis initial probability to stored prior
# If no match: use conservative defaults from hypothesis generation
```

---

## atw (Adaptive Technique Weighting)

Tracks every technique's real-world success rate.

Technique IDs use format: `"<phase>:<technique_name>"`

Examples: `"exploit:ssrf_imds_v1"`, `"zerodayhunt:jwt_confusion_rs256_hs256"`, `"recon:subdomain_bruteforce"`

**Trust levels:**
- `high`: confirmation_rate >= 0.60 (use freely)
- `medium`: confirmation_rate 0.30-0.59 (use but don't prioritize)
- `low`: confirmation_rate 0.10-0.29 (deprioritize, log attempts)
- `flagged`: confirmation_rate < 0.10 (skip unless explicitly requested)

**Update formula:**
```
confirmation_rate = confirmations / (confirmations + denials)
trust_level = high if rate >= 0.60 else medium if rate >= 0.30 else low if rate >= 0.10 else flagged
```

**How skills use this:**
```bash
# Before running a technique, check ATW
TRUST=$(jq -r '.atw["exploit:ssrf_imds_v1"].trust_level' ~/.akira/memory.json 2>/dev/null || echo "medium")

if [ "$TRUST" = "flagged" ]; then
  echo "[ATW] Skipping exploit:ssrf_imds_v1 - trust_level: flagged (confirmation_rate < 10%)"
  # Move to next technique
fi
```

---

## hallucination_guard

Tracks techniques where the AI frequently claims findings that don't survive the Precision Gate.

A technique is flagged when: `hallucination_rate = (claimed - confirmed) / claimed > 0.50`

**How `plan-engagement` uses this:**
- Flagged techniques are written into `session.json scalpel.doom_loop.flagged_techniques`
- All skills check this list before claiming a finding
- A flagged technique requires a HIGHER evidence threshold (data_access mandatory)

**How this prevents hallucination:**
- If the AI has historically over-claimed XSS findings that failed the Precision Gate,
  `hallucination_guard["exploit:xss_reflected"].flagged = true`
- Future exploit sessions see the flag and require a reproducible evidence quote before CONFIRMED

---

## waf_bypass_priors

Accumulates which bypass techniques work against which WAF vendors.

Populated when a bypass succeeds during a `/403-bypass` session.

Keys: lowercase WAF vendor name (`"cloudflare"`, `"akamai"`, `"aws_waf"`, etc.)

---

## program_patterns

Platform-level intelligence accumulated from reporting experience.

Keys: `"hackerone"`, `"bugcrowd"`, `"intigriti"`, `"private"`, etc.

Used by `/report` to adjust submission format and language.

---

## dna_registry

Global index of all confirmed Finding DNA hashes.

Before `plan-engagement` generates hypotheses, it checks if any DNA hash from this registry
matches the current target's tech fingerprint. A match boosts the corresponding hypothesis
by the stored `avg_confidence` converted to a probability delta.

Deduplication: if the same DNA hash is confirmed again on a new target, `confirmed_count` increments
and `avg_confidence` updates as a rolling average.

---

## snr_history

Aggregate Scalpel score history across all engagements.

Used to track methodology improvement over time.
Displayed in the header of every `/report` output as proof of precision.

---

## Update Protocol (run by `triage` at engagement close)

```bash
MEMORY=~/.akira/memory.json

# 1. Increment scl_id_counter by number of SCL IDs assigned this session
# 2. For each SCALPEL_CERTIFIED finding:
#    a. Upsert tech_vuln_priors with Bayesian update
#    b. Update atw.confirmation_rate for each technique used
#    c. Add to dna_registry (or increment confirmed_count if hash exists)
# 3. For each NOISE finding (failed Precision Gate):
#    b. Update atw.denials for the technique
#    c. Check if hallucination_guard threshold is breached -> set flagged=true
# 4. Update waf_bypass_priors if 403-bypass succeeded
# 5. Update snr_history with this engagement's scalpel_score
# 6. Write updated memory.json back to ~/.akira/memory.json
```

**On first run (memory.json does not exist):**
```bash
mkdir -p ~/.akira
# plan-engagement creates memory.json with defaults seeded from FINDINGS.md DNA registry
```
