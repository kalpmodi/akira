---
name: triage
description: Use when aggregating pentest findings across all phases, clustering vulnerabilities by severity, prioritizing findings for a report, or surfacing the top actionable issues from a completed scan. Also use when the user says "triage", "aggregate findings", or "what did we find".
---

# Triage

## Overview
Reads all phase summaries and raw outputs to produce a single severity-clustered findings list in `triage.md`.

## Severity Definitions
- **Critical:** Confirmed RCE, SQLi with data extracted, auth bypass
- **High:** Confirmed XSS, IDOR, exposed secrets (verified)
- **Medium:** Potential high-impact findings (flagged, not verified)
- **Low:** Info disclosure, misconfigurations

## Steps

1. **Get target** from user if not provided.

2. **Discover all phase summaries:**
   ```bash
   ls ~/pentest-toolkit/results/<target>/interesting_*.md 2>/dev/null
   ```
   Note which phases ran and which are missing — flag them in the output.

3. **Read ALL phase summaries (dynamic - picks up any phase that ran):**
   ```bash
   cat ~/pentest-toolkit/results/<target>/interesting_*.md 2>/dev/null
   ```
   This covers: recon, secrets, exploit, zerodayhunt, oauth-attacks, race-conditions, ad-attacks, and any other phases that wrote output.

4. **Read raw corroboration for CONFIRMED findings:**
   ```bash
   cat ~/pentest-toolkit/results/<target>/exploitation/nuclei.txt 2>/dev/null
   cat ~/pentest-toolkit/results/<target>/exploitation/xss.txt 2>/dev/null
   ls ~/pentest-toolkit/results/<target>/exploitation/sqlmap/ 2>/dev/null
   cat ~/pentest-toolkit/results/<target>/exploitation/zerodayhunt/*.txt 2>/dev/null
   ```

5. **Rank findings:**
   - Priority 1: CONFIRMED, ordered Critical → High
   - Priority 2: POTENTIAL, ordered by severity
   - Top 5 = highest confirmed first, padded with high-severity potentials if fewer than 5 confirmed

6. **Write `triage.md`** to `~/pentest-toolkit/results/<target>/triage.md`:

```markdown
# Triage: <target>
Date: <YYYY-MM-DD>

## Coverage
- Phases run: <list>
- Phases missing: <list or "none">

## Critical
- [CONFIRMED] <finding> — <one-line evidence>

## High
- [CONFIRMED] <finding> — <one-line evidence>
- [POTENTIAL] <finding> — <one-line reason>

## Medium
- [POTENTIAL] <finding> — ...

## Low
- [POTENTIAL] <finding> — ...

## Top 5 Actionable
1. <highest priority finding>
2. ...
```

7. **False Positive Verification Gate** - Before finalizing any finding, run this check:

   For each CONFIRMED finding:
   a. Re-read the raw tool output. Does the evidence actually show what you claimed?
   b. Ask: "Could this be a test environment, mock server, or sandbox response?"
   c. Ask: "Is the data in the response actually sensitive, or just the field name?"
   d. Assign a Confidence Score (0-100):
      - 90-100: Reproducible, full data exfil or proven RCE
      - 70-89: Strong evidence but not fully chained (e.g., SSRF confirmed, no data yet)
      - 50-69: Behavioral indicator (timing diff, error message) but no data proof
      - 0-49: Speculative, single data point, could be coincidence
   e. Downgrade any CONFIRMED finding with Confidence < 70 to POTENTIAL.

   **Common false positives to watch for:**
   - SQLi: error message contains "SQL" but came from input validation, not DB execution
   - XSS: payload reflected in response but sanitized (< escaped) before DOM insertion
   - SSRF: server connects to your IP but only because you control the domain (not internal reach)
   - IDOR: 200 response but body is YOUR data, not another user's
   - Open redirect: 302 to your URL but only from your own session (not cross-user)

8. **Confidence Score Table** - Add to triage.md:

```markdown
## Confidence Scores
| Finding | Type | Score | Rationale |
|---------|------|-------|-----------|
| XSS /search | CONFIRMED | 95 | dalfox payload in live response body |
| SQLi /login | CONFIRMED | 80 | error-based, no row extracted yet |
| SSRF /fetch | POTENTIAL | 65 | DNS OOB callback, no internal data |
```

9. Tell the user: "Triage complete. `triage.md` written. Run `/report <target>` to generate the final report."
