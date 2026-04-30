# ZDH Evidence Classification + Output + Phase-End Completion Gate

## Evidence Classification Rules

**CONFIRMED CRITICAL** (requires ALL):
- HTTP response body contains actual sensitive data
- Data is clearly sensitive (credentials, PII, internal architecture)
- Attack is reproducible with exact curl/python command

**POTENTIAL CRITICAL** = probe indicates vulnerability but no data extracted

**INFORMATIONAL** = prerequisite confirmed but exploitability unproven

**NOT A FINDING:**
- HTTP 200 with 0-byte body (WAF catch-all)
- TCP connection established (port open != access)
- DNS resolves to private IP (informational alone, not a finding)
- OOB callback received without data in body (proves SSRF exists, not Critical yet)

## Output

Write to `~/pentest-toolkit/results/<target>/interesting_zerodayhunt.md`:

```markdown
## Status
findings-present | no-findings

## Summary
<confirmed count, potential count, highest severity, key attack chain>

## Confirmed Findings
- [CONFIRMED CRITICAL] <attack type> on <endpoint>
  Chain: <how this connects to other findings>
  Evidence: <exact response snippet>
  Reproduce: <exact command>

## Potential Findings
- [POTENTIAL] <attack type> - requires <what is needed to confirm>
  Chain opportunity: <what this enables if confirmed>

## Supply Chain Surface
- <package names unclaimed on npm/Maven>
- Authorization status: pending | granted | not-applicable

## Attack Chains Identified
1. <Chain name>: <finding A> + <finding B> -> <Critical impact>

## Next Steps
1. <highest priority unconfirmed vector>
2. <authorization needed for X>
3. <chain that needs one more piece>
```

**Write confirmed findings to `session.json report_draft.findings[]` using Scalpel format immediately:**

For every CONFIRMED finding, write the canonical Scalpel Finding Record (same format as exploit skill).
Key fields specific to zerodayhunt:
- `dna.vuln_class`: use specific class (e.g., `jwt_rs256_hs256_confusion`, `prototype_pollution_rce`, `oauth_open_redirect_ato`)
- `dna.chain_fingerprint`: describe the actual chain path (e.g., `jwks_endpoint->alg_swap->admin_api`)
- `kill_chain[]`: document every step that contributed to the chain - even recon or secrets steps that enabled it
- `engagement.skills_chain`: include all skills that contributed (e.g., `["recon", "secrets", "zerodayhunt"]`)

**Doom loop guard (same as exploit):**
```bash
SESSION=~/pentest-toolkit/results/<target>/session.json
TECHNIQUE="zerodayhunt:<phase_name>"

RUNS=$(jq -r --arg t "$TECHNIQUE" '.scalpel.doom_loop.technique_runs[$t] // 0' $SESSION)
RUNS=$((RUNS + 1))
jq --arg t "$TECHNIQUE" --argjson r $RUNS '.scalpel.doom_loop.technique_runs[$t] = $r' $SESSION > /tmp/s.json && mv /tmp/s.json $SESSION

# 3+ runs on same target+technique with no new signal = doom loop
if [ $RUNS -gt 3 ]; then
  echo "[DOOM LOOP] Detected on $TECHNIQUE - routing to next hypothesis"
fi

# Increment SNR tool_runs
jq '.scalpel.snr.tool_runs += 1' $SESSION > /tmp/s.json && mv /tmp/s.json $SESSION
```

Tell user: "Zero-day hunt complete. `interesting_zerodayhunt.md` written.
Key finding: <one-liner on most critical>. Run `/triage <target>` to certify findings."

## Phase-End: Completion Gate

```bash
PENDING_MUST=$(jq '[.scalpel.active_manifest.items[] | select(.priority=="MUST" and .status=="pending")] | length' $SESSION 2>/dev/null || echo 0)
if [ "$PENDING_MUST" -gt 0 ]; then
  echo "=== COMPLETION GATE BLOCKED ==="
  echo "$PENDING_MUST MUST items not completed:"
  jq '.scalpel.active_manifest.items[] | select(.priority=="MUST" and .status=="pending") | "\(.id): \(.tool) on \(.target)"' $SESSION
  echo "Run them or mark skipped with reason before calling /triage."
fi

PENDING_SHOULD=$(jq '[.scalpel.active_manifest.items[] | select(.priority=="SHOULD" and .status=="pending")] | length' $SESSION 2>/dev/null || echo 0)
[ "$PENDING_SHOULD" -gt 0 ] && echo "WARNING: $PENDING_SHOULD SHOULD items pending"
```
