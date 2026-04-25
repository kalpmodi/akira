---
name: triage
description: Use when aggregating pentest findings across all phases, clustering vulnerabilities by severity, prioritizing findings for a report, or surfacing the top actionable issues from a completed scan. Also use when the user says "triage", "aggregate findings", or "what did we find".
---

# Triage - Scalpel Precision Engine

## Overview

Triage does three things:
1. Runs the **Precision Gate** on every finding (5 layers - no exceptions)
2. Scores **KCCG** (Kill Chain Completeness) and enforces severity caps
3. Assigns **SCL IDs**, calculates **SNR / Scalpel Score**, and writes memory updates

Output: `triage.md` in Scalpel format + memory write-back to `~/.akira/memory.json`

---

## Step 1: Load Context

```bash
TARGET=$1
SESSION=~/pentest-toolkit/results/$TARGET/session.json
RESULTS=~/pentest-toolkit/results/$TARGET
MEMORY=~/.akira/memory.json
SIGNALS_FILE=$RESULTS/signals.jsonl

# Get current SCL counter
SCL_COUNTER=$(jq -r '.scalpel.id_counter // 6' $SESSION 2>/dev/null)
YEAR=$(date +%Y)

# Get all findings from report_draft
FINDINGS=$(jq -r '.report_draft.findings' $SESSION 2>/dev/null)

# Read intel from all phases that ran
PHASES_RAN=$(ls $RESULTS/interesting_*.md 2>/dev/null | sed 's/.*interesting_//' | sed 's/\.md//')

# Redteam intel (if redteam phase ran)
if echo "$PHASES_RAN" | grep -q "redteam"; then
  DA_OBTAINED=$(jq -r '.intel_relay.from_redteam.da_credentials_obtained // false' $SESSION 2>/dev/null)
  KILL_CHAIN=$(jq -r '.intel_relay.from_redteam.kill_chain // ""' $SESSION 2>/dev/null)
  LATERAL_HOSTS=$(jq -r '.intel_relay.from_redteam.lateral_movement_hosts[]?' $SESSION 2>/dev/null | tr '\n' ',')
  RT_TECHNIQUES=$(jq -r '.intel_relay.from_redteam.techniques_used[]?' $SESSION 2>/dev/null)
  RT_PERSISTENCE=$(jq -r '.intel_relay.from_redteam.persistence_confirmed // false' $SESSION 2>/dev/null)
  RT_EXFIL=$(jq -r '.intel_relay.from_redteam.exfil_confirmed // false' $SESSION 2>/dev/null)
  echo "Redteam ran: DA=$DA_OBTAINED | persistence=$RT_PERSISTENCE | exfil=$RT_EXFIL"
  echo "Lateral hosts: $LATERAL_HOSTS"
  # Redteam kill chain + DA credentials = auto-Critical if scope valid
  [ "$DA_OBTAINED" = "true" ] && echo "[!] DA credentials confirmed - KCCG 5/5 for domain compromise chain"
fi

# Signal totals from signals.jsonl
TOTAL_SIGNALS=$(wc -l < $SIGNALS_FILE 2>/dev/null | tr -d ' ' || echo 0)
CONFIRMED_SIGNALS=$(grep '"type":"VULN_CONFIRMED"' $SIGNALS_FILE 2>/dev/null | wc -l | tr -d ' ' || echo 0)
echo "Total signals: $TOTAL_SIGNALS | VULN_CONFIRMED: $CONFIRMED_SIGNALS"
```

---

## Step 2: Discover All Phase Summaries

```bash
ls $RESULTS/interesting_*.md 2>/dev/null
cat $RESULTS/interesting_*.md 2>/dev/null
```

Note which phases ran and which are missing. Any phase that ran but is missing from `report_draft.findings[]` needs its interesting_*.md reviewed for overlooked findings.

---

## Step 3: For Each Finding - Run Precision Gate (5 Layers)

Process every entry in `report_draft.findings[]`. For each:

### Layer 1: Authenticity
- Is the HTTP response from the real live target?
- Check: no CDN cache headers (`X-Cache: HIT`, `Age: N`), no staging/test domain indicators
- Check: response body is dynamic (contains real data, not static placeholder)
- FAIL condition: response is a CDN cache hit, or host is `*.staging.*`, `*.test.*`, `*.sandbox.*`

### Layer 2: Reproducibility
- Can the exact same request sequence be replayed with the same result?
- Standard: 2/3 replays must succeed (race conditions: 1/3 minimum)
- FAIL condition: finding only occurred once and cannot be reproduced

### Layer 3: Data Sensitivity
- Is the exposed data actually sensitive?
- PASS: real credentials (verified active), real PII (name+email+address), real DB rows, real RCE output
- FAIL: field name present but value is empty/null/placeholder, dummy data in test fixture, redacted data

### Layer 4: Scope Validity
- Is the vulnerable endpoint within the declared program scope?
- Check: compare endpoint against `session.json program` and known scope
- FAIL: endpoint is on out-of-scope domain, `*.sandbox.*`, CDN origin, third-party service not in scope

### Layer 5: KCCG Threshold
- See KCCG scoring in Step 4

**Precision Gate result:**
- All 5 layers PASS -> `status: "SCALPEL_CERTIFIED"`, assign SCL ID
- 1-2 layers FAIL -> `status: "POTENTIAL"`, document which layers failed and why
- 3+ layers FAIL -> `status: "NOISE"`, exclude from report, log for ATW update

---

## Step 4: KCCG Score (Kill Chain Completeness Graph)

For each finding, evaluate 5 completeness steps:

| Step | What it means | Evidence required |
|------|--------------|-------------------|
| `initial_access` | Entry point found and confirmed reachable | Specific endpoint/parameter that takes attacker input |
| `escalation` | Privilege gained or auth bypassed | Credential extraction, auth token forged, role elevated |
| `data_access` | Real impact demonstrated | PII accessed, credentials verified live, DB rows extracted, RCE output |
| `reproducible` | Chain works on replay | 2/3 replays succeed (race: 1/3) |
| `scope_valid` | Target in declared scope | Endpoint matches program scope definition |

**KCCG score = steps_completed / 5**

**Severity caps:**
- KCCG 1.0 (5/5) - severity as claimed (Critical allowed)
- KCCG 0.8 (4/5) - severity capped at **High** (data_access not yet proven)
- KCCG 0.6 (3/5) - severity capped at **Medium**
- KCCG < 0.6 - severity capped at **Low / Informational**

**Common cap triggers:**
- SSRF confirmed but no metadata/internal data yet -> KCCG 0.8 -> cap at High
- XSS reflected but no sensitive data accessed -> KCCG 0.8 -> cap at High
- JWT confusion forge works but no admin endpoint tested -> KCCG 0.8 -> cap at High

Write KCCG result back to the finding record in `session.json`.

---

## Step 5: Assign SCL IDs and Calculate DNA Hashes

For each `SCALPEL_CERTIFIED` finding:

```bash
# Assign SCL ID
SCL_ID="SCL-${YEAR}-$(printf "%03d" $SCL_COUNTER)"
SCL_COUNTER=$((SCL_COUNTER + 1))

# Generate DNA hash
# Combine: vuln_class + tech_fingerprint (sorted) + chain_fingerprint
DNA_INPUT="${vuln_class}:${tech_fingerprint_sorted}:${chain_fingerprint}"
DNA_HASH="sha256:$(echo -n "$DNA_INPUT" | sha256sum | cut -d' ' -f1)"
```

Write `scl_id` and `dna.hash` back to the finding in `session.json report_draft.findings[]`.

---

## Step 6: Calculate SNR / Scalpel Score

```bash
# Read from session.json scalpel.snr
TOOL_RUNS=$(jq -r '.scalpel.snr.tool_runs // 1' $SESSION)
SIGNALS=$(jq -r '.scalpel.snr.signals_emitted // 0' $SESSION)
CONFIRMED=$(jq '.report_draft.findings | map(select(.status=="SCALPEL_CERTIFIED")) | length' $SESSION)
NOISE=$(jq '.report_draft.findings | map(select(.status=="NOISE")) | length' $SESSION)
POTENTIAL=$(jq '.report_draft.findings | map(select(.status=="POTENTIAL")) | length' $SESSION)

# Calculate
YIELD_RATE=$(echo "scale=3; $SIGNALS / $TOOL_RUNS" | bc 2>/dev/null || echo "0.000")
CONVERSION_RATE=$(echo "scale=3; $CONFIRMED / ($SIGNALS + 0.001)" | bc 2>/dev/null || echo "0.000")
NOISE_PENALTY=$(echo "scale=3; $NOISE / ($CONFIRMED + $NOISE + 0.001)" | bc 2>/dev/null || echo "0.000")
SCALPEL_SCORE=$(echo "scale=0; ($CONVERSION_RATE * 100) * (1 - $NOISE_PENALTY) / 1" | bc 2>/dev/null || echo "0")
```

**Scalpel score interpretation:**
- 80-100: Surgical - excellent hypothesis quality, minimal noise
- 60-79: Precise - good signal discipline, minor noise
- 40-59: Noisy - hypothesis breadth too wide
- Below 40: Undisciplined - technique selection needs review

---

## Step 7: Write triage.md

Write to `$RESULTS/triage.md`:

```markdown
# Triage: <target>
**Date:** <YYYY-MM-DD>
**Scalpel Score:** <score>/100 (<interpretation>)

---

## Coverage
- **Phases run:** <list>
- **Phases missing:** <list or "none">

---

## Scalpel Certified Findings

### Critical

#### [SCL-YYYY-NNN] <Title>
**KCCG:** 5/5 | **Confidence:** <N>/100 | **DNA:** sha256:<hash truncated to 16 chars>...
**Kill Chain:** <step 1> -> <step 2> -> <step 3>
**Evidence:** <one-line direct quote from HTTP response or tool output>
**PoC:** `pocs/SCL-YYYY-NNN.<sh|py>`

### High
...same format...

---

## Potential Findings (Precision Gate Incomplete)

- [POTENTIAL] <title> - Failed layers: <Layer N: reason>, <Layer M: reason>
  - To upgrade: <specific evidence needed to pass failed layers>

---

## Noise (Excluded)

- [NOISE] <title> - Failed layers: <3+ reasons> - Excluded from report

---

## SNR Summary

| Metric | Value |
|--------|-------|
| Tool runs | <N> |
| Signals emitted | <N> |
| SCL Certified | <N> |
| Potential | <N> |
| Noise | <N> |
| Yield rate | <N>% |
| Conversion rate | <N>% |
| **Scalpel Score** | **<N>/100** |

---

## Top 5 Actionable

1. [SCL-YYYY-NNN] <highest severity certified finding>
2. ...
```

---

## Step 8: Generate PoC Files

For each `SCALPEL_CERTIFIED` finding:

```bash
mkdir -p $RESULTS/pocs

# Bash PoC
cat > $RESULTS/pocs/${SCL_ID}_poc.sh << 'EOF'
#!/bin/bash
# SCL ID: <scl_id>
# DNA: <hash>
# Chain: <chain_fingerprint>
# Reproduced: <date>

TARGET="${1:-https://target.com}"

# Step 1: <technique>
# <actual curl/command from kill_chain[0]>

# Step 2: <technique>
# <actual curl/command from kill_chain[1]>

echo "Full chain complete. Evidence in: $RESULTS/http-responses/"
EOF
chmod +x $RESULTS/pocs/${SCL_ID}_poc.sh

# HTTP file (for Burp/Repeater)
# Write raw HTTP requests from kill_chain[] steps
```

---

## Step 9: Write Memory Updates to ~/.akira/memory.json

At engagement close, update cross-engagement intelligence:

```bash
MEMORY=~/.akira/memory.json

# Initialize if not exists
[ ! -f $MEMORY ] && mkdir -p ~/.akira && echo '{"version":"1.0","scl_id_counter":1,"tech_vuln_priors":{},"atw":{},"hallucination_guard":{},"waf_bypass_priors":{},"program_patterns":{},"dna_registry":[],"snr_history":{"all_time_avg_scalpel_score":0,"total_engagements":0,"total_certified_findings":0,"total_false_positives":0}}' > $MEMORY
```

**For each SCALPEL_CERTIFIED finding - concrete write-back:**

```bash
TECH="<vuln_class_from_finding>"    # e.g. "ssrf", "jwt_confusion", "kerberoast"
VULN_CLASS="<class>"                # e.g. "injection", "auth_bypass", "ad_attack"

# 1. Update ATW confirmation rate for each technique in kill chain
for TECH in $(jq -r ".report_draft.findings[] | select(.status==\"SCALPEL_CERTIFIED\") | .kill_chain[]?" $SESSION 2>/dev/null); do
  CONFS=$(jq -r ".atw[\"$TECH\"].confirmations // 0" $MEMORY)
  DENIALS=$(jq -r ".atw[\"$TECH\"].denials // 0" $MEMORY)
  TOTAL=$(( CONFS + DENIALS + 1 ))
  NEW_CONFS=$(( CONFS + 1 ))
  RATE=$(echo "scale=3; $NEW_CONFS / $TOTAL" | bc)
  jq --arg t "$TECH" --argjson c "$NEW_CONFS" --argjson r "$RATE" \
    '.atw[$t] = (.atw[$t] // {}) + {"confirmations":$c,"trust_level":"confirmed","confirmation_rate":$r}' \
    $MEMORY > /tmp/m.json && mv /tmp/m.json $MEMORY
done

# 2. Upsert tech_vuln_priors (Bayesian update: new_p = (prior * n + evidence) / (n + 1))
jq --arg tech "$TECH" --arg vuln "$VULN_CLASS" \
  '.tech_vuln_priors[$tech] = (.tech_vuln_priors[$tech] // {"base_probability":0.4,"last_seen":null,"count":0}) |
   .tech_vuln_priors[$tech].count += 1 |
   .tech_vuln_priors[$tech].last_seen = now | todate |
   .tech_vuln_priors[$tech].base_probability = (
     [(.tech_vuln_priors[$tech].base_probability * .tech_vuln_priors[$tech].count + 0.85) /
      (.tech_vuln_priors[$tech].count + 1), 0.85] | min
   )' $MEMORY > /tmp/m.json && mv /tmp/m.json $MEMORY

# 3. Upsert DNA registry
DNA_HASH="<calculated in Step 5>"
jq --arg h "$DNA_HASH" --arg t "$TARGET" \
  '(.dna_registry[] | select(.dna==$h)) |= . + {"confirmed_count": (.confirmed_count + 1), "last_seen":now | todate} //
   .dna_registry += [{"dna":$h,"target":$t,"confirmed_count":1,"first_seen":now | todate,"last_seen":now | todate}]' \
  $MEMORY > /tmp/m.json && mv /tmp/m.json $MEMORY
```

**For each NOISE finding - hallucination guard update:**

```bash
for TECH in $(jq -r ".report_draft.findings[] | select(.status==\"NOISE\") | .technique?" $SESSION 2>/dev/null); do
  CONFS=$(jq -r ".atw[\"$TECH\"].confirmations // 0" $MEMORY)
  DENIALS=$(jq -r ".atw[\"$TECH\"].denials // 0" $MEMORY)
  NEW_DENIALS=$(( DENIALS + 1 ))
  TOTAL=$(( CONFS + NEW_DENIALS ))
  # Hallucination guard: if denial rate > 50% -> flag technique
  DENIAL_RATE=$(echo "scale=3; $NEW_DENIALS / $TOTAL" | bc)
  FLAGGED=$(echo "$DENIAL_RATE > 0.5" | bc)
  jq --arg t "$TECH" --argjson d "$NEW_DENIALS" --argjson f "$FLAGGED" \
    '.atw[$t] = (.atw[$t] // {}) + {"denials":$d} |
     if $f == 1 then .atw[$t].trust_level = "flagged" | .hallucination_guard[$t] = {"flagged":true,"denial_rate":($d|tonumber)} else . end' \
    $MEMORY > /tmp/m.json && mv /tmp/m.json $MEMORY
done
```

**Update global counters and prior decay:**

```bash
# Increment SCL counter
jq ".scl_id_counter = $SCL_COUNTER" $MEMORY > /tmp/m.json && mv /tmp/m.json $MEMORY

# Update SNR history
TOTAL_ENG=$(jq -r '.snr_history.total_engagements // 0' $MEMORY)
TOTAL_CERT=$(jq -r '.snr_history.total_certified_findings // 0' $MEMORY)
TOTAL_FP=$(jq -r '.snr_history.total_false_positives // 0' $MEMORY)
PREV_AVG=$(jq -r '.snr_history.all_time_avg_scalpel_score // 0' $MEMORY)
NEW_ENG=$(( TOTAL_ENG + 1 ))
NEW_CERT=$(( TOTAL_CERT + $(jq '.report_draft.findings | map(select(.status=="SCALPEL_CERTIFIED")) | length' $SESSION) ))
NEW_FP=$(( TOTAL_FP + $(jq '.report_draft.findings | map(select(.status=="NOISE")) | length' $SESSION) ))
NEW_AVG=$(echo "scale=1; ($PREV_AVG * $TOTAL_ENG + $SCALPEL_SCORE) / $NEW_ENG" | bc)
jq --argjson ne "$NEW_ENG" --argjson nc "$NEW_CERT" --argjson nf "$NEW_FP" --argjson na "$NEW_AVG" \
  '.snr_history = {"total_engagements":$ne,"total_certified_findings":$nc,"total_false_positives":$nf,"all_time_avg_scalpel_score":$na}' \
  $MEMORY > /tmp/m.json && mv /tmp/m.json $MEMORY

# Prior decay - run on every memory write
TODAY=$(date +%s)
jq --argjson today "$TODAY" '
  .tech_vuln_priors |= with_entries(
    if .value.last_seen != null then
      .value.days_old = (($today - (.value.last_seen | fromdateiso8601)) / 86400 | floor) |
      if .value.days_old > 180 then
        .value.decay_weight = ([0.7, (1.0 - (.value.days_old / 365.0) * 0.3)] | max) |
        .value.base_probability = (.value.base_probability * .value.decay_weight)
      else . end
    else . end
  )' $MEMORY > /tmp/m.json && mv /tmp/m.json $MEMORY
```

---

## Step 10: Report to User

```
Triage complete.

SCL Certified:  <N> findings
Potential:      <N> findings (Precision Gate incomplete)
Noise:          <N> excluded
Scalpel Score:  <N>/100 (<interpretation>)

Memory updated: ~/.akira/memory.json
PoC files:      ~/pentest-toolkit/results/<target>/pocs/

Run /report <target> to generate the final report.
```
