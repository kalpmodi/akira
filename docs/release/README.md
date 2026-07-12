# Release Hygiene

This document defines release criteria, changelog process, and adapter compatibility expectations.

---

## Release Criteria by Version

| Release | Status | Exit Criteria |
|---|---|---|
| Basilisk v1.1.0 | In Development | Technique library split complete, shared Phase 0 enforced in core pipeline, race-proof signal handling validated, `/redteam` integration stable |
| Raven v1.2.0 | Planned | Context engine persistence across engagements, automated tech-fingerprint learning, `cache-attacks` + `csp-bypass` skills with evidence-driven outputs |
| Phantom v1.3.0 | Planned | Mobile DAST skill quality gate, Burp MCP event feed to `session.json`, cross-phase relay integrity checks |
| Leviathan v2.0.0 | Planned | Autonomous multi-skill orchestration, doom-loop predictor model in active routing, persistent attack tree with deterministic replay |

---

## Changelog Automation Policy

1. Every PR must include a changelog intent:
   - feature, fix, docs, or internal
2. Release prep PR must:
   - move completed items from "Upcoming" to a released section
   - include a migration/compatibility note if command behavior changed
3. Keep release section naming consistent with roadmap (`In Development`, `Planned`, `Shipped`).
4. Review `toolchain/versions.env` in each release train and bump intentionally (no silent latest drift).

---

## Adapter Compatibility Matrix

| Adapter | Path | Current Compatibility Note |
|---|---|---|
| Claude Code | `install.sh`, `~/.claude/skills/` | Primary adapter; full skill-chain support |
| Cursor | `platform-adapters/.cursor/rules/akira.mdc` | Rules-based activation; keep command aliases in sync with core skills |
| Gemini CLI | `platform-adapters/GEMINI.md` | Prompt adapter; verify examples after every major routing change |
| Codex/OpenAI Agents | `platform-adapters/.codex/INSTALL.md` + `AGENTS.md` | Generic adapter path; keep capability and safety language aligned with core docs |

---

## Validation Checklist Before Release Tag

- Run `python3 .github/scripts/validate_repo_quality.py`
- Run shell syntax checks:
  - `bash -n install.sh bootstrap.sh skills/_shared/phase0.sh skills/_shared/signals.sh`
- Confirm roadmap table in `README.md` matches `CHANGELOG.md` upcoming statuses.
- Confirm adapter docs still reflect active skill names and lifecycle order.
