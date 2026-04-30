# Intelligence Protocol — Cross-Skill Coordination Contract

Every skill in Akira follows this protocol. Not following it is the root cause of
missed tools, mechanical execution, and phases that "run" but don't actually do the work.

---

## The Core Problem This Solves

Without this protocol, skills run like this:
1. Run wrapper script (`secrets.sh`)
2. Read output
3. Stop (because output looks like "enough")
4. Never run GitHub dorking, API spec hunting, Postman scanning, etc.

With this protocol, skills run like this:
1. Read EVERYTHING from prior phases — extract specific targets
2. Build a targeted manifest BEFORE running a single tool
3. Execute every manifest item — no skipping, no early exits
4. Write structured intel relay for the next phase
5. Verify completion BEFORE finishing

---

## Phase 0: Smart Intake (Every Skill Starts Here)

Before running any tool, every skill MUST build a targeted picture from prior phases.
This replaces the weak "read session.json" blocks that existed before.

```bash
TARGET=$1
SESSION=~/pentest-toolkit/results/$TARGET/session.json
RESULTS=~/pentest-toolkit/results/$TARGET

# ── Core state ───────────────────────────────────────────────────────────────
STATE=$(jq -r '.engagement_state // "WIDE"' $SESSION 2>/dev/null)
HYPOTHESES=$(jq -r '.hypotheses | sort_by(-.probability) | .[] | select(.status=="active") | "\(.id)[\((.probability*100)|round)%] \(.label)"' $SESSION 2>/dev/null)
FLAGGED_TECHNIQUES=$(jq -r '.scalpel.doom_loop.flagged_techniques[]?' $SESSION 2>/dev/null)

# ── Intel Relay (pre-digested output from prior phases) ──────────────────────
RELAY=$(jq -r '.intel_relay' $SESSION 2>/dev/null)

# Phase-specific extractions — each skill runs only its relevant block:
# (see per-skill intake sections below)

echo "=== SMART INTAKE: $TARGET ==="
echo "State: $STATE"
echo "Active hypotheses:"
echo "$HYPOTHESES"
echo "ATW flagged: ${FLAGGED_TECHNIQUES:-none}"
```

**State gate — run FIRST, before anything else:**
- `HARVEST` → do not run this skill. Evidence extraction only. Exit immediately.
- `DEEP` → targeted mode. Only work the active hypothesis chain. Skip broad sweeps.
- `WIDE` → full execution. Run everything in the manifest.
- `WRAP` → drain queued items only. No new technique discovery.

---

## Execution Manifest

After Smart Intake, every skill MUST generate a manifest and write it to session.json.
This is the enforcement mechanism — every item must be completed before the phase ends.

### Manifest Format

```json
"scalpel": {
  "active_manifest": {
    "phase": "<skill_name>",
    "generated_at": "<YYYY-MM-DD HH:MM>",
    "items": [
      {
        "id": "m01",
        "tool": "trufflehog",
        "target": "<specific URL or path>",
        "reason": "<why this target — derived from intel>",
        "priority": "MUST|SHOULD|IF_TIME",
        "status": "pending|done|skipped",
        "skip_reason": null
      }
    ]
  }
}
```

### Priority Levels

- `MUST` — non-negotiable. Phase cannot end with this item pending.
- `SHOULD` — important. Skip only with explicit documented reason.
- `IF_TIME` — optional. Skip if engagement_state is DEEP or HARVEST.

### How to Write the Manifest

```bash
# Generate manifest items based on smart intake findings
# Write to session.json before running any tool
MANIFEST=$(cat << 'MANIFEST_EOF'
{
  "phase": "<skill>",
  "generated_at": "YYYY-MM-DD HH:MM",
  "items": [
    <one item per tool per target>
  ]
}
MANIFEST_EOF
)

jq --argjson m "$MANIFEST" '.scalpel.active_manifest = $m' $SESSION > /tmp/s.json && mv /tmp/s.json $SESSION
```

### How to Check Off Items

After each tool runs:
```bash
jq --arg id "m01" --arg status "done" \
  '.scalpel.active_manifest.items = [.scalpel.active_manifest.items[] | if .id == $id then .status = $status else . end]' \
  $SESSION > /tmp/s.json && mv /tmp/s.json $SESSION
```

---

## Completion Gate (Every Skill Ends Here)

Before ANY phase can end, run this check. No exceptions.

```bash
# Check for pending MUST items
PENDING_MUST=$(jq '[.scalpel.active_manifest.items[] | select(.priority=="MUST" and .status=="pending")] | length' $SESSION 2>/dev/null || echo 0)

if [ "$PENDING_MUST" -gt 0 ]; then
  echo "=== COMPLETION GATE BLOCKED ==="
  echo "$PENDING_MUST MUST-priority items not completed:"
  jq '.scalpel.active_manifest.items[] | select(.priority=="MUST" and .status=="pending") | "\(.id): \(.tool) on \(.target)"' $SESSION
  echo ""
  echo "Options: run them now, OR skip with documented reason (requires explicit justification)"
  # Do not exit until all MUST items are done or explicitly skipped with reason
fi

# Check SHOULD items
PENDING_SHOULD=$(jq '[.scalpel.active_manifest.items[] | select(.priority=="SHOULD" and .status=="pending")] | length' $SESSION 2>/dev/null || echo 0)
[ "$PENDING_SHOULD" -gt 0 ] && echo "WARNING: $PENDING_SHOULD SHOULD-priority items not completed (acceptable but suboptimal)"
```

---

## Wrapper Script Fallback Protocol

Skills like secrets and exploit reference wrapper scripts (`secrets.sh`, `exploit.sh`).
These scripts may not exist, may fail, or may not run all tools correctly.

**Rule: Never trust a wrapper script result without verifying individual tool outputs.**

```bash
# Try wrapper script first
~/pentest-toolkit/<phase>/<phase>.sh $TARGET
WRAPPER_EXIT=$?

if [ $WRAPPER_EXIT -ne 0 ] || [ ! -s $RESULTS/<phase>/<key_output>.json ]; then
  echo "[FALLBACK] Wrapper script failed or produced empty output — running tools directly"
  # Execute each manifest item individually using direct tool commands
  # Do NOT stop here. The fallback is the real work.
fi

# Even if wrapper succeeded, verify specific tool outputs exist:
# Missing = that tool didn't run inside the wrapper = run it directly
```

---

## Intel Relay Schema

Written by each skill at phase end. Read by the NEXT skill in Smart Intake.
This replaces "read interesting_recon.md and figure it out yourself."

```json
"intel_relay": {
  "from_recon": {
    "js_bundle_urls": [],
    "github_orgs": [],
    "live_hosts_with_tech": [
      {"host": "api.target.com", "tech": ["aws", "node.js"], "status": 200}
    ],
    "interesting_endpoints": [],
    "cloud_hints": {"aws": false, "gcp": false, "azure": false},
    "waf": null,
    "open_ports": {},
    "parameter_names": [],
    "wayback_api_endpoints": []
  },
  "from_secrets": {
    "verified_credentials": [],
    "api_spec_endpoints": [],
    "jwt_tokens": [],
    "aws_keys_found": false,
    "github_secrets_found": false,
    "postman_collections": []
  },
  "from_exploit": {
    "ssrf_vectors": [],
    "confirmed_vulns": [],
    "internal_ips": [],
    "verified_auth_bypass": false
  }
}
```

Written incrementally — each phase adds its section. Later phases read all sections.

### How to Write Intel Relay

```bash
# At end of recon phase:
JS_BUNDLES=$(grep -oE "https?://[^ \"']*.js" $RESULTS/interesting_recon.md 2>/dev/null | sort -u | jq -R . | jq -s .)
GITHUB_ORGS=$(grep -oE "github\.com/([a-zA-Z0-9_-]+)" $RESULTS/recon/github/dorks.txt 2>/dev/null | awk -F/ '{print $2}' | sort -u | jq -R . | jq -s .)
LIVE_WITH_TECH=$(jq '[.[] | {host: .url, tech: (.tech // []), status: .status_code}]' $RESULTS/recon/httpx-full.json 2>/dev/null || echo "[]")
AWS_HINT=$(grep -qi "aws\|s3\|lambda" $RESULTS/recon/tech-stack.txt 2>/dev/null && echo true || echo false)

jq --argjson js "$JS_BUNDLES" \
   --argjson orgs "$GITHUB_ORGS" \
   --argjson hosts "$LIVE_WITH_TECH" \
   --argjson aws "$AWS_HINT" \
   '.intel_relay.from_recon = {
     "js_bundle_urls": $js,
     "github_orgs": $orgs,
     "live_hosts_with_tech": $hosts,
     "cloud_hints": {"aws": $aws}
   }' $SESSION > /tmp/s.json && mv /tmp/s.json $SESSION
```

---

## Per-Skill Smart Intake Blocks

### Secrets Phase Smart Intake

```bash
# Extract specific targets from recon intel relay
JS_BUNDLES=$(jq -r '.intel_relay.from_recon.js_bundle_urls[]?' $SESSION 2>/dev/null)
GITHUB_ORGS=$(jq -r '.intel_relay.from_recon.github_orgs[]?' $SESSION 2>/dev/null)
LIVE_HOSTS=$(jq -r '.intel_relay.from_recon.live_hosts_with_tech[] | .host' $SESSION 2>/dev/null | head -30)
AWS_HINT=$(jq -r '.intel_relay.from_recon.cloud_hints.aws // false' $SESSION 2>/dev/null)
TOP_TECH=$(jq -r '.intel.technologies[]?' $SESSION 2>/dev/null | head -10)

# Build targeted manifest:
# - TruffleHog on EACH discovered JS bundle (not generic domain scan)
# - Gitleaks on EACH discovered GitHub org
# - Postman search for target company name
# - API spec check on EACH live host
# - AWS-specific patterns IF aws_hint=true
# - .env file check on EACH live host

echo "Secrets targets:"
echo "  JS bundles: $(echo "$JS_BUNDLES" | wc -l)"
echo "  GitHub orgs: $(echo "$GITHUB_ORGS" | wc -w)"
echo "  Live hosts: $(echo "$LIVE_HOSTS" | wc -l)"
echo "  AWS mode: $AWS_HINT"
```

### Exploit Phase Smart Intake

```bash
# Extract what secrets found
VERIFIED_CREDS=$(jq -r '.intel_relay.from_secrets.verified_credentials[]? | "\(.type): \(.value[:30])"' $SESSION 2>/dev/null)
API_ENDPOINTS=$(jq -r '.intel_relay.from_secrets.api_spec_endpoints[]?' $SESSION 2>/dev/null)
JWT_TOKENS=$(jq -r '.intel_relay.from_secrets.jwt_tokens[]?' $SESSION 2>/dev/null)

# Also read direct session intel
KNOWN_CREDS=$(jq -r '.intel.credentials[]? | "\(.type): \(.value[:30])"' $SESSION 2>/dev/null)
TOP_HYPOTHESIS=$(jq -r '.hypotheses | sort_by(-.probability) | .[0] | "\(.id)[\((.probability*100)|round)%] \(.label) — test: \(.evidence_required)"' $SESSION 2>/dev/null)
ATW_FLAGGED=$(jq -r '.scalpel.doom_loop.flagged_techniques[]?' $SESSION 2>/dev/null)

echo "Exploit intake:"
echo "  Verified creds: $(echo "$VERIFIED_CREDS" | wc -l)"
echo "  API endpoints: $(echo "$API_ENDPOINTS" | wc -l)"
echo "  JWT tokens: $(echo "$JWT_TOKENS" | wc -l)"
echo "  Top hypothesis: $TOP_HYPOTHESIS"
echo "  ATW flagged (avoid): $ATW_FLAGGED"
```

### ZeroDayHunt Phase Smart Intake

```bash
# Full picture from all prior phases
ALL_CONFIRMED=$(jq -r '.report_draft.findings[] | select(.status=="confirmed") | .title' $SESSION 2>/dev/null)
SSRF_VECTORS=$(jq -r '.intel_relay.from_exploit.ssrf_vectors[]?' $SESSION 2>/dev/null)
INTERNAL_IPS=$(jq -r '.intel_relay.from_exploit.internal_ips[]?' $SESSION 2>/dev/null)
TECH_STACK=$(jq -r '.intel.technologies[]?' $SESSION 2>/dev/null | tr '\n' ',')
ALL_ENDPOINTS=$(cat $RESULTS/interesting_recon.md $RESULTS/interesting_secrets.md $RESULTS/interesting_exploit.md 2>/dev/null | grep -oE "https?://[^ \"']+" | sort -u | head -50)

echo "ZeroDayHunt intake:"
echo "  Prior confirmed findings: $(echo "$ALL_CONFIRMED" | wc -l)"
echo "  SSRF vectors to chain: $(echo "$SSRF_VECTORS" | wc -l)"
echo "  Internal IPs for SSRF: $(echo "$INTERNAL_IPS" | wc -w)"
echo "  Full tech stack: $TECH_STACK"
```

---

## Signal Emission Contract

Every skill MUST emit these minimum signals before finishing.
If a signal can't be emitted, log why in `tested_surfaces[]`.

| Skill | Must emit (if applicable) | Condition |
|-------|--------------------------|-----------|
| recon | `SURFACE_FOUND` | For each live host found |
| recon | `TECH_DETECTED` | For each confirmed technology |
| recon | `WAF_CONFIRMED` | If WAF detected in httpx output |
| secrets | `CRED_FOUND` | For each verified credential |
| secrets | `JWT_FOUND` | If JWT in any response |
| exploit | `SSRF_VECTOR` | If SSRF confirmed |
| exploit | `VULN_CONFIRMED` | If finding reaches CONFIRMED status |
| any | `INTERNAL_IP` | If private IP discovered |

If no signals were emitted by end of phase → increment `snr.tool_runs` without `snr.signals_emitted`.
This drives the SNR/Scalpel score down — a signal that the technique selection needs review.

---

## Common Failure Modes (What This Protocol Prevents)

| Failure | Root cause | Protocol fix |
|---------|-----------|--------------|
| TruffleHog not run | AI stopped after wrapper script output | Manifest makes TruffleHog a MUST item |
| GitHub dorking skipped | AI treated Step 3 output as "enough" | Completion gate blocks phase end |
| Wrong targets scanned | AI used generic domain instead of specific JS URLs | Smart Intake extracts specific URLs from intel relay |
| Repeated same technique | No doom loop detection | ATW + doom_loop.flagged_techniques |
| Next phase starts cold | No structured handoff | Intel Relay written at phase end |
| Hallucinated finding | No evidence quote | Precision Gate in triage rejects it |
