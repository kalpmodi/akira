# Akira - Codex / OpenAI Agent Install

## Setup

1. Clone this repo into your project:
   ```bash
   git clone https://github.com/Kalp1774/akira .akira
   ```

2. Reference Akira in your `AGENTS.md` or system prompt:
   ```
   Security testing skills are available in .akira/skills/.
   For pentesting tasks, read the relevant SKILL.md file and follow it.
   ```

3. Or add to your Codex system context:
   ```
   When the user asks about security testing or bug bounty, read the relevant
   skill from .akira/skills/<skill-name>/SKILL.md and follow its instructions.
   ```

## Skill Files

All skill logic is in `skills/<skill-name>/SKILL.md`. Each file is self-contained.

## Phase Chain

```
plan-engagement -> recon -> secrets -> exploit -> zerodayhunt -> triage -> report
```

## For Authorized Use Only

Only on bug bounty programs, authorized pentests, and CTF competitions.
