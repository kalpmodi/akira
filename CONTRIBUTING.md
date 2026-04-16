# Contributing to Akira

Akira improves because real bug hunters contribute real techniques from real engagements.
No CLA. No corporate process. Just open a PR.

---

## Ways to Contribute

### 1. Fix a Skill Bug
A skill claimed a finding without evidence? Missed something obvious? Gave wrong tool syntax?

- Open an issue with the `skill-bug` template
- Or directly fix `skills/<skill-name>/SKILL.md` and open a PR

### 2. Add a Technique to an Existing Skill
Know a technique that belongs in one of the current skills?

- Add it to the relevant section in `skills/<skill-name>/SKILL.md`
- Follow the existing format (bash code blocks + evidence requirement)
- Open a PR

### 3. Submit a Finding to FINDINGS.md
Found a real bug using Akira? This is the most valuable contribution.

After responsible disclosure:
1. Open an issue with the `finding-submission` template
2. Or directly open a PR adding your entry to FINDINGS.md
3. Use the existing entry format (anonymized is fine)

Attribution always included. Bounty amount is optional.

### 4. Write a New Skill
Check the roadmap in README. If it's planned, open an issue to claim it before writing.
If it's not on the roadmap but should exist, open a `new-skill` issue first to discuss.

New skill format:
```
skills/
  <skill-name>/
    SKILL.md    <- the skill logic
```

SKILL.md structure:
```markdown
---
name: skill-name
description: Use when... Also use when user says "..."
---

# Skill Title

## Philosophy
One paragraph on the mindset for this attack surface.

## Arguments
`<target>` - description
`<focus>` - optional: OPTION1 / OPTION2

---

## Phase 1 - ...

[bash code blocks with exact commands]

---

## Output

Write to `~/pentest-toolkit/results/<target>/interesting_<skill-name>.md`:

[output schema]

Tell user: "..."
```

### 5. Improve Platform Adapters
Better Cursor rules, Gemini adapter, or new platform support (Windsurf, Continue.dev, etc.)?
Open a PR against `platform-adapters/`.

---

## Standards

**Evidence requirement (non-negotiable):**
Every technique in a skill must produce verifiable evidence.
- Show the exact HTTP request/response that proves the finding
- Document what distinguishes a true positive from a false positive
- If evidence is behavioral (timing, OOB), document how to confirm it

**Format consistency:**
- Follow the existing SKILL.md structure
- Use bash code blocks for commands
- Use `<target>` as placeholder for the target domain/IP
- Output files go to `~/pentest-toolkit/results/<target>/`

**No hallucination:**
Don't add techniques that are speculative or unverified.
Every technique should have been run against a real target (even a lab/CTF counts).

---

## PR Review

PRs are reviewed by the maintainer within a few days.
If your PR adds a finding to FINDINGS.md - instant merge (after basic check).
If your PR improves an existing skill - fast review.
If your PR adds a new skill - reviewed carefully for quality and completeness.

---

## Questions?

Open a GitHub Discussion. Issues are for bugs and requests, not questions.
