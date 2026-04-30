# Fork Protocol — Inter-Skill Signal Standard

This document is the contract every Akira skill follows for emitting signals, spawning forks, reading intel, and writing back findings. Read this before implementing any cross-phase behavior.

---

## Every skill must do these 4 things

### 1. Read session.json at the start

Before taking any action:

```bash
SESSION=$(cat ~/pentest-toolkit/results/<target>/session.json)
STATE=$(echo $SESSION | jq -r '.engagement_state')
BUDGET_ACTIVE=$(echo $SESSION | jq -r '.fork_budget.active')
BUDGET_MAX=$(echo $SESSION | jq -r '.fork_budget.max')
```

Then:
- If `STATE == "DEEP"` → do not fork new surfaces, queue them
- If `STATE == "HARVEST"` → do not fork anything, collect evidence only
- Read `intel` block to avoid rediscovering what's already known
- Read `hypotheses` to know what you're trying to confirm or deny

### 2. Check dedup before every action

```bash
# Before testing api.target.com/admin with jwt_confusion:
ALREADY_TESTED=$(cat session.json | jq '.tested_surfaces[] | select(.surface == "api.target.com/admin" and .action == "exploit:jwt_confusion")')

if [ -n "$ALREADY_TESTED" ]; then
  echo "Already tested — skipping"
  # move to next action
fi
```

If already in `tested_surfaces` → skip, move on. No retries.

### 3. Emit a signal for every meaningful discovery

Signal emission format (append to `session.json.signals[]`):

```json
{
  "id": "sig-<NNN>",
  "type": "<SIGNAL_TYPE>",
  "value": "<what was found — specific, not vague>",
  "confidence": <0-100>,
  "emitted_by": "<thread_id>/<phase>",
  "timestamp": "<YYYY-MM-DD HH:MM>",
  "consumed_by": [],
  "triggered": null
}
```

Signal threshold — emit when:
- A new host, endpoint, or IP is discovered
- A credential, key, or token is found
- A technology is fingerprinted with confidence
- A WAF or CDN is confirmed
- An injection point or SSRF vector is found
- A vulnerability is confirmed with HTTP proof

Do NOT emit signals for: failed attempts, 404s, timeouts, irrelevant noise.

After emitting, immediately check correlation rules (Step 6 in plan-engagement/SKILL.md). If a pattern matches — act on it before continuing.

### 4. Write to tested_surfaces after every completed action

Whether the action succeeded or failed:

```json
{
  "surface": "<target/path or host:port>",
  "action": "<phase>:<technique_name>",
  "result": "<200 found creds | 403 still | RS256 not present | timeout>",
  "thread": "<thread_id>",
  "timestamp": "<YYYY-MM-DD HH:MM>"
}
```

This is mandatory. Missing entries cause duplicate work across forks.

---

## How to spawn a fork

### Check budget first

```bash
ACTIVE=$(cat session.json | jq -r '.fork_budget.active')
MAX=$(cat session.json | jq -r '.fork_budget.max')
STATE=$(cat session.json | jq -r '.engagement_state')

if [ "$STATE" = "DEEP" ] || [ "$STATE" = "HARVEST" ]; then
  # Do not fork — write to discovery_queue instead
elif [ "$ACTIVE" -lt "$MAX" ]; then
  # Fork is allowed — proceed
else
  # Budget full — write to discovery_queue with priority score
fi
```

### Confidence tiers

| Confidence | What to do |
|---|---|
| < 40% | Write to `discovery_queue`, notify user, no fork |
| 40-70% | Shallow fork — single targeted check only |
| > 70% | Full fork — run complete phase on new surface |

### Priority score for discovery_queue

```
priority = (impact_score × confidence) / estimated_token_cost

impact_score:
  INTERNAL_IP with SSRF → 95
  CRED_FOUND new surface → 90
  new subdomain → 70
  new endpoint → 50
  new JS file → 40

estimated_token_cost:
  shallow check → 1
  full recon → 3
  full exploit → 5
```

### Write the fork brief — keep it under 80 tokens

This is what you pass to the forked agent. Be minimal. The fork does not need the full session.json.

```
FORK: fork-<N>
Target: <specific host, IP, or file being investigated>
Phase: <recon | secrets | exploit | cloud-audit | 403-bypass>
Trigger: sig-<NNN> — <one line: what was found that caused this>
Hypothesis: H<N> — <one line: what this fork is testing>
Known intel: tech=[...], creds=[...], waf=<value or null>
Write back: ~/pentest-toolkit/results/<target>/session.json
  → signals[] for discoveries
  → threads[fork-<N>] for status updates
  → tested_surfaces[] for every action taken
Dedup: check tested_surfaces[] before every action
Mode: emit signals and write findings. No narration. Be minimal.
```

### Update session.json when spawning

```json
// Increment fork_budget.active
// Add thread entry:
{
  "id": "fork-N",
  "target": "<target>",
  "phase": "<phase>",
  "status": "running",
  "parent": "<spawning_thread_id>",
  "genealogy": ["main", "fork-1", "fork-N"],
  "trigger": "sig-NNN",
  "health": {"steps_since_signal": 0, "status": "healthy"}
}

// Add PTT node:
{
  "id": "fork-N",
  "label": "<target> via <trigger>",
  "children": [],
  "status": "running",
  "trigger": "sig-NNN"
}
```

---

## How to write back findings

When a vulnerability is confirmed, write immediately to `report_draft.findings[]`. Do not wait for /report.

```json
{
  "id": "F<N>",
  "title": "<concise finding name>",
  "severity": "Critical | High | Medium | Low | Info",
  "hypothesis": "H<N>",
  "attack_chain": [
    "<step 1: initial vector>",
    "→ <step 2: pivot or escalation>",
    "→ <step 3: impact demonstrated>"
  ],
  "evidence_signals": ["sig-001", "sig-004"],
  "http_proof": "<path to saved request/response in http-responses/>",
  "screenshot": "<path or null>",
  "status": "confirmed",
  "confirmed_at": "<timestamp>"
}
```

Then update the hypothesis:
```json
{"id": "H1", "status": "confirmed", "probability": 1.0}
```

---

## How to handle dead-end detection

Every skill must track its own health:

```bash
# After each step, check if a signal was emitted
# If not: increment health.steps_since_signal in session.json threads[<id>]
# If yes: reset health.steps_since_signal to 0, set status "healthy"

STEPS_SILENT=$(cat session.json | jq --arg tid "$THREAD_ID" '.threads[] | select(.id == $tid) | .health.steps_since_signal')

if [ "$STEPS_SILENT" -ge 8 ]; then
  # Log remaining untested paths to tested_surfaces with result: "abandoned - low yield"
  # Set thread status: "terminated"
  # Decrement fork_budget.active
  # Signal main thread: slot reclaimed
fi
```

---

## How to update hypotheses after a signal

After emitting or receiving any signal, recalibrate all hypotheses whose `boosted_by` list includes the signal type:

```python
for hypothesis in session["hypotheses"]:
    if signal["type"] in hypothesis["boosted_by"]:
        # Specificity check: does signal value match evidence_required?
        if evidence_match(signal["value"], hypothesis["evidence_required"]):
            hypothesis["probability"] = min(1.0, hypothesis["probability"] + 0.20)
            hypothesis["supporting_signals"].append(signal["id"])
        else:
            hypothesis["probability"] = min(1.0, hypothesis["probability"] + 0.10)

    # Check for denial
    if contradicts(signal, hypothesis):
        hypothesis["probability"] = max(0.0, hypothesis["probability"] - 0.30)
        hypothesis["denying_signals"].append(signal["id"])

    # Trigger state transitions
    if hypothesis["probability"] >= 0.85 and hypothesis["status"] == "active":
        session["engagement_state"] = "DEEP"
    if hypothesis["probability"] <= 0.10:
        hypothesis["status"] = "denied"
```

---

## Phase-end checklist (every skill runs this before finishing)

1. All discovered surfaces emitted as `SURFACE_FOUND` signals? Yes / No
2. All credentials emitted as `CRED_FOUND`? Yes / No
3. All technologies written to `intel.technologies[]`? Yes / No
4. All tested paths written to `tested_surfaces[]`? Yes / No
5. Hypotheses recalibrated against new signals? Yes / No
6. Any confirmed findings written to `report_draft.findings[]`? Yes / No
7. Fork slots still open + engagement state is WIDE → check `discovery_queue` for queued items to fork
8. Thread `health.status` still healthy? If low_yield → consider terminating

If all checked: update `threads[<id>].phase` to next phase, set `status: "done"` for this phase.
