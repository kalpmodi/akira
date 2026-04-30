#!/usr/bin/env bash
# Akira signal emission library - append-only signals.jsonl (race-proof)
# Source alongside phase0.sh: source ~/.claude/skills/_shared/signals.sh
# Requires: SIGNALS_FILE set by p0_init_vars

# ── emit_signal TYPE VALUE SOURCE [CONFIDENCE] ────────────────────────────────
# Appends one signal line to SIGNALS_FILE. No read-modify-write = race-proof.
# TYPE:   SURFACE_FOUND | CRED_FOUND | TECH_DETECTED | WAF_CONFIRMED |
#         INTERNAL_IP | JWT_FOUND | SSRF_VECTOR | AUTH_BYPASS | VULN_CONFIRMED
# VALUE:  the discovered value (host, credential snippet, tech name, etc.)
# SOURCE: "main/recon", "fork-1/exploit", etc.
# CONFIDENCE: 0.0-1.0 (default 0.7)
emit_signal() {
  local type="$1" value="$2" source="$3" confidence="${4:-0.7}"
  local ts sig_id
  ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  sig_id="sig-$(date +%s%3N)"
  printf '{"id":"%s","ts":"%s","type":"%s","value":"%s","source":"%s","confidence":%s}\n' \
    "$sig_id" "$ts" "$type" "$value" "$source" "$confidence" >> "$SIGNALS_FILE"
  echo "[SIGNAL] $type | $value | src=$source | conf=$confidence"
}

# ── read_signals [TYPE] ───────────────────────────────────────────────────────
# Prints .value for each signal, optionally filtered by type.
read_signals() {
  [ ! -f "$SIGNALS_FILE" ] && return 0
  if [ -n "$1" ]; then
    jq -r "select(.type==\"$1\") | .value" "$SIGNALS_FILE" 2>/dev/null
  else
    jq -r '.value' "$SIGNALS_FILE" 2>/dev/null
  fi
}

# ── count_signals [TYPE] ──────────────────────────────────────────────────────
count_signals() {
  [ ! -f "$SIGNALS_FILE" ] && echo 0 && return 0
  if [ -n "$1" ]; then
    jq -r "select(.type==\"$1\") | .id" "$SIGNALS_FILE" 2>/dev/null | wc -l | tr -d ' '
  else
    wc -l < "$SIGNALS_FILE" | tr -d ' '
  fi
}

# ── check_pattern TYPE1 TYPE2 ─────────────────────────────────────────────────
# Returns 0 (true) if both signal types exist - for correlation rule checks.
check_pattern() {
  [ "$(count_signals "$1")" -gt 0 ] && [ "$(count_signals "$2")" -gt 0 ]
}

# ── signals_init ──────────────────────────────────────────────────────────────
# Creates signals.jsonl if it doesn't exist (idempotent).
signals_init() {
  touch "$SIGNALS_FILE" 2>/dev/null || true
}

# ── signals_summary ───────────────────────────────────────────────────────────
# Prints a count breakdown of all signal types seen so far.
signals_summary() {
  [ ! -f "$SIGNALS_FILE" ] && echo "No signals yet." && return 0
  echo "=== Signal Summary: $TARGET ==="
  for t in SURFACE_FOUND CRED_FOUND TECH_DETECTED WAF_CONFIRMED INTERNAL_IP JWT_FOUND SSRF_VECTOR AUTH_BYPASS VULN_CONFIRMED; do
    local c; c=$(count_signals "$t")
    [ "$c" -gt 0 ] && echo "  $t: $c"
  done
  echo "  TOTAL: $(count_signals)"
}
