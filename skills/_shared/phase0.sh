#!/usr/bin/env bash
# Akira Phase 0 shared intake library
# Source at the start of every skill: source ~/.claude/skills/_shared/phase0.sh
# Then call: p0_init_vars "$TARGET" && p0_state_gate || exit 0

# ── p0_init_vars TARGET ───────────────────────────────────────────────────────
# Sets: TARGET, SESSION, RESULTS, MEMORY, SIGNALS_FILE, LOOT
p0_init_vars() {
  export TARGET="$1"
  export SESSION=~/pentest-toolkit/results/$TARGET/session.json
  export RESULTS=~/pentest-toolkit/results/$TARGET
  export MEMORY=~/.akira/memory.json
  export SIGNALS_FILE=$RESULTS/signals.jsonl
  export LOOT=$RESULTS/loot
}

# ── p0_state_gate [BLOCKED_STATES...] ────────────────────────────────────────
# Default blocks on HARVEST. Returns 1 (exit phase) if blocked.
# Usage: p0_state_gate || exit 0
# Usage: p0_state_gate "HARVEST WRAP" || exit 0
p0_state_gate() {
  export STATE=$(jq -r '.engagement_state // "WIDE"' "$SESSION" 2>/dev/null || echo "WIDE")
  local blocked="${1:-HARVEST}"
  for s in $blocked; do
    [ "$STATE" = "$s" ] && echo "[AKIRA] State=$STATE - this phase is blocked" && return 1
  done
  return 0
}

# ── p0_read_memory ────────────────────────────────────────────────────────────
# Sets: SCL_COUNTER, FLAGGED_TECH, HIGH_PRIOR_TECH, PRIOR_DNAS, ATW_FLAGGED
p0_read_memory() {
  export SCL_COUNTER=$(jq -r '.scl_id_counter // 1' "$MEMORY" 2>/dev/null || echo 1)
  export FLAGGED_TECH=$(jq -r '.atw | to_entries[] | select(.value.trust_level=="flagged") | .key' "$MEMORY" 2>/dev/null)
  export HIGH_PRIOR_TECH=$(jq -r '.tech_vuln_priors | to_entries | sort_by(-.value.base_probability) | .[0:3] | .[] | "\(.key): \(.value.base_probability)"' "$MEMORY" 2>/dev/null)
  export PRIOR_DNAS=$(jq -r '.dna_registry[].dna' "$MEMORY" 2>/dev/null | head -5)
  export ATW_FLAGGED=$(jq -r '.scalpel.doom_loop.flagged_techniques[]?' "$SESSION" 2>/dev/null)
}

# ── p0_read_relay PHASE [PHASE ...] ──────────────────────────────────────────
# Reads intel_relay from named prior phases into named exports.
# Supported: recon, secrets, exploit, cloud_audit, redteam
p0_read_relay() {
  for phase in "$@"; do
    case "$phase" in
      recon)
        export JS_BUNDLES=$(jq -r '.intel_relay.from_recon.js_bundle_urls[]?' "$SESSION" 2>/dev/null)
        export GITHUB_ORGS=$(jq -r '.intel_relay.from_recon.github_orgs[]?' "$SESSION" 2>/dev/null)
        export LIVE_HOSTS=$(jq -r '.intel_relay.from_recon.live_hosts_with_tech[] | .host' "$SESSION" 2>/dev/null | head -30)
        export INTERESTING_ENDPOINTS=$(jq -r '.intel_relay.from_recon.interesting_endpoints[]?' "$SESSION" 2>/dev/null | head -30)
        export WAYBACK_ENDPOINTS=$(jq -r '.intel_relay.from_recon.wayback_api_endpoints[]?' "$SESSION" 2>/dev/null | head -20)
        export PARAM_NAMES=$(jq -r '.intel_relay.from_recon.parameter_names[]?' "$SESSION" 2>/dev/null | head -20)
        export AWS_HINT=$(jq -r '.intel_relay.from_recon.cloud_hints.aws // false' "$SESSION" 2>/dev/null)
        export GCP_HINT=$(jq -r '.intel_relay.from_recon.cloud_hints.gcp // false' "$SESSION" 2>/dev/null)
        export AZURE_HINT=$(jq -r '.intel_relay.from_recon.cloud_hints.azure // false' "$SESSION" 2>/dev/null)
        export WAF=$(jq -r '.intel.waf // "none"' "$SESSION" 2>/dev/null)
        # Fallbacks from interesting_recon.md
        [ -z "$JS_BUNDLES" ] && export JS_BUNDLES=$(grep -oE "https?://[^ \"']*\.js[^\"' ]*" "$RESULTS/interesting_recon.md" 2>/dev/null | sort -u | head -30)
        [ -z "$GITHUB_ORGS" ] && export GITHUB_ORGS=$(grep -oE "github\.com/([a-zA-Z0-9_-]+)" "$RESULTS/interesting_recon.md" 2>/dev/null | awk -F/ '{print $2}' | sort -u)
        [ -z "$LIVE_HOSTS" ] && export LIVE_HOSTS=$(cat "$RESULTS/recon/live-hosts.txt" 2>/dev/null | awk '{print $3}' | head -30)
        ;;
      secrets)
        export VERIFIED_CREDS=$(jq -r '.intel_relay.from_secrets.verified_credentials[]? | "\(.type): \(.value[:40])"' "$SESSION" 2>/dev/null)
        export JWT_TOKENS=$(jq -r '.intel_relay.from_secrets.jwt_tokens[]?' "$SESSION" 2>/dev/null | head -5)
        export AWS_KEYS_FOUND=$(jq -r '.intel_relay.from_secrets.aws_keys_found // false' "$SESSION" 2>/dev/null)
        export API_SPEC_ENDPOINTS=$(jq -r '.intel_relay.from_secrets.api_spec_endpoints[]?' "$SESSION" 2>/dev/null | head -50)
        export POSTMAN_COLLECTIONS=$(jq -r '.intel_relay.from_secrets.postman_collections[]?' "$SESSION" 2>/dev/null)
        ;;
      exploit)
        export CONFIRMED_VULNS=$(jq -r '.intel_relay.from_exploit.confirmed_vulns[]?' "$SESSION" 2>/dev/null)
        export INTERNAL_IPS=$(jq -r '.intel_relay.from_exploit.internal_ips[]?' "$SESSION" 2>/dev/null)
        export SSRF_VECTORS=$(jq -r '.intel_relay.from_exploit.ssrf_vectors[]?' "$SESSION" 2>/dev/null)
        export VERIFIED_AUTH_BYPASS=$(jq -r '.intel_relay.from_exploit.verified_auth_bypass // false' "$SESSION" 2>/dev/null)
        # Fallback from intel
        [ -z "$INTERNAL_IPS" ] && export INTERNAL_IPS=$(jq -r '.intel.internal_ips[]?' "$SESSION" 2>/dev/null)
        ;;
      cloud_audit)
        export CLOUD_CREDS=$(jq -r '.intel_relay.from_cloud_audit.cloud_credentials[]?' "$SESSION" 2>/dev/null)
        export CLOUD_PRIVESC=$(jq -r '.intel_relay.from_cloud_audit.privesc_confirmed // false' "$SESSION" 2>/dev/null)
        export CLOUD_DATA=$(jq -r '.intel_relay.from_cloud_audit.data_accessed[]?' "$SESSION" 2>/dev/null)
        export CLOUD_PRIVESC_PATH=$(jq -r '.intel_relay.from_cloud_audit.privesc_path // ""' "$SESSION" 2>/dev/null)
        ;;
      redteam)
        export DA_OBTAINED=$(jq -r '.intel_relay.from_redteam.da_credentials_obtained // false' "$SESSION" 2>/dev/null)
        export DA_CREDS=$(jq -r '.intel_relay.from_redteam.da_credentials // ""' "$SESSION" 2>/dev/null)
        export LATERAL_HOSTS=$(jq -r '.intel_relay.from_redteam.lateral_movement_hosts[]?' "$SESSION" 2>/dev/null)
        export KILL_CHAIN=$(jq -r '.intel_relay.from_redteam.kill_chain // ""' "$SESSION" 2>/dev/null)
        export RT_TECHNIQUES=$(jq -r '.intel_relay.from_redteam.techniques_used[]?' "$SESSION" 2>/dev/null)
        export RT_PERSISTENCE=$(jq -r '.intel_relay.from_redteam.persistence_confirmed // false' "$SESSION" 2>/dev/null)
        export RT_EXFIL=$(jq -r '.intel_relay.from_redteam.exfil_confirmed // false' "$SESSION" 2>/dev/null)
        ;;
    esac
  done
}

# ── p0_read_hypotheses ────────────────────────────────────────────────────────
# Sets: HYPOTHESES, TOP_HYPO_LABEL, TOP_HYPO_PROB, KNOWN_TECH
p0_read_hypotheses() {
  export HYPOTHESES=$(jq -r '.hypotheses | sort_by(-.probability) | .[] | select(.status=="active") | "\(.id)[\((.probability*100)|round)%] \(.label)"' "$SESSION" 2>/dev/null)
  export TOP_HYPO_LABEL=$(jq -r '.hypotheses | sort_by(-.probability) | .[0].label' "$SESSION" 2>/dev/null)
  export TOP_HYPO_PROB=$(jq -r '.hypotheses | sort_by(-.probability) | .[0] | (.probability*100|round)' "$SESSION" 2>/dev/null)
  export KNOWN_TECH=$(jq -r '.intel.technologies[]?' "$SESSION" 2>/dev/null | tr '\n' ',')
}

# ── p0_manifest_write PHASE ITEMS_JSON ───────────────────────────────────────
# Writes manifest to session.json scalpel.active_manifest
# ITEMS_JSON: JSON array of manifest item objects
p0_manifest_write() {
  local phase="$1" items_json="$2"
  local ts; ts=$(date '+%Y-%m-%d %H:%M')
  local full_manifest
  full_manifest=$(printf '{"phase":"%s","generated_at":"%s","items":%s}' "$phase" "$ts" "$items_json")
  jq --argjson m "$full_manifest" '.scalpel.active_manifest = $m' "$SESSION" > /tmp/_p0_s.json && mv /tmp/_p0_s.json "$SESSION"
}

# ── p0_mark_done ITEM_ID ──────────────────────────────────────────────────────
# Marks a manifest item done in session.json
p0_mark_done() {
  jq --arg id "$1" '(.scalpel.active_manifest.items[] | select(.id==$id) | .status) = "done"' \
    "$SESSION" > /tmp/_p0_s.json && mv /tmp/_p0_s.json "$SESSION"
}

# ── p0_mark_skipped ITEM_ID REASON ───────────────────────────────────────────
p0_mark_skipped() {
  jq --arg id "$1" --arg r "$2" \
    '(.scalpel.active_manifest.items[] | select(.id==$id)) |= . + {"status":"skipped","skip_reason":$r}' \
    "$SESSION" > /tmp/_p0_s.json && mv /tmp/_p0_s.json "$SESSION"
}

# ── p0_completion_gate ────────────────────────────────────────────────────────
# Returns 1 and prints blocking message if any MUST item is still pending.
# Returns 0 if clear to proceed to phase-end.
p0_completion_gate() {
  local pending
  pending=$(jq -r '.scalpel.active_manifest.items[]? | select(.priority=="MUST" and .status=="pending") | .id' "$SESSION" 2>/dev/null)
  if [ -n "$pending" ]; then
    echo "[COMPLETION GATE BLOCKED] Pending MUST items: $pending"
    echo "Complete all MUST items before ending this phase."
    return 1
  fi
  echo "[COMPLETION GATE CLEAR]"
  return 0
}

# ── p0_relay_write PHASE KEY VALUE ───────────────────────────────────────────
# Writes a value into intel_relay.from_<phase>.<key> in session.json
# For array append: p0_relay_append PHASE KEY VALUE
p0_relay_write() {
  local phase="$1" key="$2" value="$3"
  jq --arg v "$value" ".intel_relay.from_${phase}.${key} = \$v" \
    "$SESSION" > /tmp/_p0_s.json && mv /tmp/_p0_s.json "$SESSION"
}

p0_relay_append() {
  local phase="$1" key="$2" value="$3"
  jq --arg v "$value" ".intel_relay.from_${phase}.${key} += [\$v]" \
    "$SESSION" > /tmp/_p0_s.json && mv /tmp/_p0_s.json "$SESSION"
}
