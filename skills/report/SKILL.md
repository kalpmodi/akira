---
name: report
description: Use when generating a pentest report, writing up findings from a completed assessment, converting triage output into a structured document, or producing an executive summary of vulnerabilities. Also use when the user says "generate report", "write report", or "create report".
---

# Report Generator

## Overview
Reads `triage.md` and optionally `plan.md` to produce a structured markdown pentest report.

## Steps

1. **Get target and report mode from user if not provided.**
   - Ask: "Full pentest report or Bug Bounty submission format (HackerOne/Bugcrowd)?"

2. **Read triage.md (required):**
   ```bash
   cat ~/pentest-toolkit/results/<target>/triage.md
   ```
   If missing: stop and tell the user to run `/triage <target>` first.

3. **Read plan.md (optional):**
   ```bash
   cat ~/pentest-toolkit/results/<target>/plan.md 2>/dev/null
   ```
   If missing: scope section reads "Quick engagement — no scope document recorded."

4. **Get today's date:**
   ```bash
   date +%Y-%m-%d
   ```

5. **Write report** to `~/pentest-toolkit/results/<target>/report-<YYYY-MM-DD>.md`:

```markdown
# Penetration Test Report: <target>
**Date:** <YYYY-MM-DD>
**Assessor:** Red Team

---

## Executive Summary
**Scope:** <from plan.md, or "Quick engagement — no scope document recorded">
**Assessment Period:** <date>
**Findings Summary:**
| Severity | Confirmed | Potential |
|----------|-----------|-----------|
| Critical | N | N |
| High | N | N |
| Medium | N | N |
| Low | N | N |

<2-3 sentence summary of most critical findings and overall risk posture>

---

## Findings Table
| ID | Title | Severity | CVSS | Status |
|----|-------|----------|------|--------|
| F-01 | <title> | Critical | 9.8 | Confirmed |

---

## Finding Details

### F-01: <Title>
**Severity:** Critical
**CVSS Score:** <score> (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
**Status:** Confirmed
**Description:** <what the vulnerability is>
**Impact:** <business impact - what an attacker can do>
**Evidence:** <direct quote or reference from tool output>
**Steps to Reproduce:**
1. <step 1>
2. <step 2>
3. <observed result>
**Remediation:** <specific fix recommendation>

---

## Methodology Notes
**Phases Completed:** <list from triage coverage section>
**Phases Skipped:** <list or "none">
**Tools Used:** subfinder, dnsx, httpx, nmap, gau, katana, tlsx, trufflehog, gitleaks, feroxbuster, arjun, dalfox, nuclei, sqlmap
**Coverage Gaps:** <anything not tested>
```

If zero high/critical findings: exec summary reads "No critical or high severity findings were identified during this assessment."

**Bug Bounty Mode** - if user selected bug bounty format, write `~/pentest-toolkit/results/<target>/bugbounty-<YYYY-MM-DD>.md` instead:

```markdown
# Bug Report: <Title of Vulnerability>

**Severity:** Critical / High / Medium / Low
**CVSS Score:** <score> (<vector string>)
**Asset:** <affected domain/endpoint>
**Weakness:** CWE-<number> - <name>

## Summary
<2-3 sentences. What is the vulnerability and what can an attacker do with it?>

## Steps to Reproduce
1. Navigate to <url>
2. <action>
3. Observe: <what happens>

## Impact
<Business impact. Be specific: "An attacker can read all user PII including emails and billing addresses" not just "data exposure">

## Supporting Evidence
<Screenshot description / curl command / tool output snippet>
```bash
<proof of concept command>
```

## Suggested Fix
<Specific, actionable remediation>
```

6. Tell the user: "Report written to `~/pentest-toolkit/results/<target>/report-<date>.md`."
