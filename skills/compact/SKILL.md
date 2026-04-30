---
name: compact
description: Use when context is running long during a pentest engagement, at phase boundaries after completing a full phase, or when the user says "compact", "compress context", "trim context", or "save tokens". Compresses completed phase outputs while keeping session.json as the authoritative source of truth.
---

# Compact - Context Compaction

## Overview

Long engagements burn context fast. This skill compresses completed phase outputs
into a single `engagement_summary.md` without losing any certified intelligence.

Rule: `session.json` is always the authoritative source of truth.
After compaction, the AI re-reads `session.json` instead of relying on conversation history.

---

## When to Trigger

Auto-trigger at these moments:
- After completing any full phase (recon, secrets, exploit, zerodayhunt)
- When `session.json signals[]` exceeds 30 entries
- When the user asks explicitly
- Before spawning a new fork (give the fork a clean context budget)

---

## Steps

1. **Get target:**
   ```bash
   TARGET=$1
   SESSION=~/pentest-toolkit/results/$TARGET/session.json
   RESULTS=~/pentest-toolkit/results/$TARGET
   ```

2. **Identify completed phases:**
   ```bash
   ls $RESULTS/interesting_*.md 2>/dev/null
   ```

3. **For each completed phase - compress to 5 bullet signals:**

   Read each `interesting_<phase>.md` and distill to essential intelligence only:

   ```
   RECON SIGNALS (from interesting_recon.md):
   - Live hosts: <N> discovered, key: <most interesting>
   - Tech stack: <comma-separated confirmed tech>
   - WAF: <vendor or null>
   - Key endpoints: <top 3>
   - Hypothesis calibration: H1 <N>%, H2 <N>%

   SECRETS SIGNALS (from interesting_secrets.md):
   - Credentials found: <Y/N>, type: <aws_key|jwt|password>
   - Key files: <source locations>
   - Cloud provider confirmed: <Y/N>

   EXPLOIT SIGNALS (from interesting_exploit.md):
   - Confirmed findings: <N>, classes: <list>
   - SSRF vectors: <Y/N>, endpoints: <list>
   - Potential findings: <N>
   ```

4. **Write `engagement_summary.md`:**
   ```bash
   cat > $RESULTS/engagement_summary.md << EOF
   # Engagement Summary: $TARGET
   Compacted: $(date +%Y-%m-%d\ %H:%M)
   Source of truth: session.json

   ## Phase Intelligence (Compressed)
   <5-bullet summaries per completed phase>

   ## Active Hypotheses
   <from session.json hypotheses[] - all active ones with current probability>

   ## Confirmed Findings
   <from session.json report_draft.findings[] - title + severity + status per finding>

   ## Open Discovery Queue
   <from session.json discovery_queue[] - surface + priority per item>

   ## Signal Summary
   Total signals: <N>
   Critical signals: <list VULN_CONFIRMED + CRED_FOUND entries>

   ## Next Recommended Action
   <based on engagement_state and top hypothesis probability>
   EOF
   ```

5. **Purge completed phase files from active context** (they are now in engagement_summary.md):
   - Do NOT delete the files - they stay on disk for triage
   - Simply note: "Context compacted. Phase files remain at $RESULTS/ — reread session.json for current state."

6. **Rehydrate from session.json:**
   ```bash
   # Re-read key session fields after compaction
   STATE=$(jq -r '.engagement_state' $SESSION)
   TOP_HYPO=$(jq -r '.hypotheses | sort_by(-.probability) | .[0] | "\(.id)[\((.probability*100)|round)%] \(.label)"' $SESSION)
   DRAFT_COUNT=$(jq '.report_draft.findings | length' $SESSION)
   SCALPEL_SCORE=$(jq -r '.scalpel.snr.scalpel_score // "pending"' $SESSION)

   echo "State: $STATE | Top: $TOP_HYPO | Draft findings: $DRAFT_COUNT | Scalpel: $SCALPEL_SCORE"
   ```

7. **Filter for certified findings only:**

   If compaction is triggered after `/triage` has run:
   - Only `SCALPEL_CERTIFIED` findings persist in active context
   - `NOISE` findings are dropped entirely
   - `POTENTIAL` findings are compressed to one line each

8. **Tell the user:**
   ```
   Context compacted. <N> phase files compressed to engagement_summary.md.
   Session.json remains authoritative — <N> signals, <N> draft findings.
   Scalpel Score so far: <N>/100
   Continuing from: <engagement_state> state, top hypothesis: <label> at <N>%
   ```
