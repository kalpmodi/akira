---
name: report
description: Use when generating a pentest report, writing up findings from a completed assessment, converting triage output into a structured document, or producing an executive summary of vulnerabilities. Also use when the user says "generate report", "write report", or "create report".
---

# Report Generator

## Overview

Reads `triage.md` (required) and `session.json` to produce a structured report.
80-90% of content is pre-filled from `report_draft.findings[]` - this skill formats and narratizes, it does not discover.

## Steps

1. **Get target and report mode from user if not provided.**
   - Ask: "Full pentest report or Bug Bounty submission format (HackerOne/Bugcrowd)?"

2. **Read triage.md (required):**
   ```bash
   cat ~/pentest-toolkit/results/<target>/triage.md
   ```
   If missing: stop and tell the user to run `/triage <target>` first.

3. **Read session.json for Scalpel stats:**
   ```bash
   SESSION=~/pentest-toolkit/results/<target>/session.json
   SCALPEL_SCORE=$(jq -r '.scalpel.snr.scalpel_score // "N/A"' $SESSION 2>/dev/null)
   CERTIFIED=$(jq '.report_draft.findings | map(select(.status=="SCALPEL_CERTIFIED")) | length' $SESSION 2>/dev/null)
   ```

4. **Read plan.md (optional):**
   ```bash
   cat ~/pentest-toolkit/results/<target>/plan.md 2>/dev/null
   ```

5. **Get today's date:**
   ```bash
   date +%Y-%m-%d
   ```

6. **Write report** to `~/pentest-toolkit/results/<target>/report-<YYYY-MM-DD>.md`:

```markdown
# Penetration Test Report: <target>
**Date:** <YYYY-MM-DD>
**Assessor:** Akira / Red Team

---

## Scalpel Assessment Quality

| Metric | Value |
|--------|-------|
| Scalpel Score | <N>/100 |
| Certified Findings (SCL) | <N> |
| False Positives | 0 |
| KCCG Complete | <N>/<N> |

> Every finding below is Scalpel Certified — 5-layer Precision Gate passed,
> full Kill Chain proven, DNA fingerprinted, PoC generated.

---

## Executive Summary
**Scope:** <from plan.md, or "Quick engagement — no scope document recorded">
**Assessment Period:** <date>

<2-3 sentence summary of most critical certified findings and overall risk posture>

**Findings Summary:**

| Severity | SCL Certified | Potential |
|----------|--------------|-----------|
| Critical | <N> | <N> |
| High | <N> | <N> |
| Medium | <N> | <N> |
| Low | <N> | <N> |

---

## Certified Findings

### [SCL-YYYY-NNN] <Title>

```
SCALPEL CERTIFIED  [SCL-YYYY-NNN]
Severity:    <Critical|High|Medium|Low>
KCCG:        <N>/5  (<severity> certified)
Confidence:  <N> / 100
DNA:         <hash truncated>...
PoC:         pocs/<SCL-YYYY-NNN>_poc.sh
```

**Severity:** <severity>
**CVSS Estimate:** <score> (AV:N/AC:L/PR:N/UI:N/...)
**Asset:** <affected endpoint>
**Weakness:** CWE-<N> — <name>

**Description:** <what the vulnerability is>

**Kill Chain:**
1. <step 1: technique and action>
2. <step 2: technique and action>
3. <step 3: technique and action>

**Impact:** <business impact — specific: "An attacker can extract AWS IAM credentials and access production S3 buckets containing customer database backups">

**Evidence:**
```
<direct HTTP response quote or tool output — must be from kill_chain evidence>
```

**Steps to Reproduce:**
```bash
# See pocs/<SCL-YYYY-NNN>_poc.sh for full reproduction script
# Key commands:
<step 1 command>
<step 2 command>
```

**Remediation:** <specific actionable fix>

---

## Potential Findings (Precision Gate Incomplete)

For each POTENTIAL finding from triage.md:

### <Title>

**Status:** POTENTIAL — Precision Gate incomplete
**Failed layers:** <Layer N: reason>
**What's needed to certify:** <specific evidence required to pass failed layers>
**Current evidence:** <what was found so far>
**Recommended next step:** <specific test to run>

---

## Methodology

**Phases Completed:** <from triage coverage section>
**Phases Skipped:** <list or "none">
**Skills Chain:** <skills used, e.g., /recon -> /secrets -> /exploit -> /zerodayhunt>
**Tools Used:** subfinder, dnsx, httpx, nmap, gau, katana, trufflehog, gitleaks, feroxbuster, arjun, dalfox, nuclei, sqlmap, jwt_tool, httpx, naabu
**Scalpel Architecture:** Every finding requires 5-layer Precision Gate + KCCG completeness before certification. Zero hallucinations — no claim without HTTP proof.

---

## PoC Index

| SCL ID | File | Type | Size |
|--------|------|------|------|
| <SCL-YYYY-NNN> | pocs/<SCL-YYYY-NNN>_poc.sh | Bash | - |
| <SCL-YYYY-NNN> | pocs/<SCL-YYYY-NNN>_poc.http | Raw HTTP | - |
```

**Bug Bounty Mode** — if user selected bug bounty format, write `bugbounty-<YYYY-MM-DD>.md` instead with one file per finding:

```markdown
# Bug Report: <Title>

**SCL ID:** SCL-YYYY-NNN
**Severity:** Critical / High / Medium / Low
**CVSS Score:** <score> (<vector string>)
**Asset:** <affected domain/endpoint>
**Weakness:** CWE-<N> - <name>
**DNA:** sha256:<hash>... (unique fingerprint — not a duplicate)

## Summary
<2-3 sentences: what is the vulnerability and what can an attacker do?>

## Kill Chain
1. <step 1>
2. <step 2>
3. <step 3: impact demonstrated>

## Steps to Reproduce
<numbered steps — match kill_chain exactly>

## Impact
<Specific: "An attacker can..." not "data exposure">

## Supporting Evidence
```
<HTTP proof — exact response fragment from precision gate evidence>
```

```bash
<PoC command from poc.sh>
```

## Suggested Fix
<Specific, actionable>

## Notes
KCCG: <N>/5 - Full kill chain proven
Reproducible: Yes (<N>/3 replays)
Scalpel Score: <N>/100
```

7. Tell the user: "Report written to `~/pentest-toolkit/results/<target>/report-<date>.md`."
