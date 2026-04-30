---
name: _shared
description: Internal utility library - not an invokable skill. Contains phase0.sh (session state, intel relay, memory read) and signals.sh (append-only signal emission). Sourced by all other skills via `source ~/.claude/skills/_shared/phase0.sh`.
---

# Shared Utility Library

This directory contains bash libraries sourced by all Akira skills. It is not an invokable skill.

## Files

- `phase0.sh` - canonical Phase 0 functions: `p0_init_vars`, `p0_state_gate`, `p0_read_relay`, `p0_read_memory`, `p0_read_hypotheses`, `p0_manifest_write`, `p0_relay_write`, `p0_completion_gate`
- `signals.sh` - atomic append-only signal emission: `emit_signal TYPE VALUE SOURCE CONFIDENCE`

## Usage

```bash
source ~/.claude/skills/_shared/phase0.sh
source ~/.claude/skills/_shared/signals.sh
```
