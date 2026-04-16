---
name: plan-engagement
description: Use when starting a pentesting engagement, receiving a target domain or IP to assess, needing to decide which pentest phases to run, scoping a red team assessment, or creating a structured engagement plan before running any tools. Also use when the user says "new engagement", "start a pentest", or "plan this target".
---

# Plan Engagement

## Overview
Creates a structured engagement plan for a target before any tools run. For quick bug bounty targets, skips the plan doc and jumps straight to recon.

## Steps

1. **Ask the user:**
   - "Quick mode (skip plan, jump straight to /recon) or Full mode (generate plan doc)?"
   - Target domain or IP
   - Scope notes (in-scope hosts, out-of-scope, any constraints)

2. **Quick mode:** Tell the user to run `/recon <target>` and stop here. Do not create plan.md.

3. **Full mode:** Create the results directory and write the plan:

```bash
mkdir -p ~/pentest-toolkit/results/<target>
```

Write `~/pentest-toolkit/results/<target>/plan.md` with this structure:

```markdown
# Engagement Plan: <target>
Date: <YYYY-MM-DD>

## Scope
<in-scope hosts, IP ranges, constraints>

## Phases
- [ ] Phase 1: Recon — /recon <target>
- [ ] Phase 2: Secrets — /secrets <target>
- [ ] Phase 3: Exploitation — /exploit <target>
- [ ] Phase 3b (optional): Zero-Day Hunt — /zerodayhunt <target>
- [ ] Phase 3c (optional): OAuth Attacks — /oauth-attacks <target>
- [ ] Phase 3d (optional): Race Conditions — /race-conditions <target>
- [ ] Phase 3e (optional): AD Attacks — /ad-attacks <target>
- [ ] Phase 4: Triage — /triage <target>
- [ ] Phase 5: Report — /report <target>

## Notes
<any special flags, exclusions, client constraints>
```

4. **Initialize Pentest Task Tree (PTT) and session.json:**

   Create `~/pentest-toolkit/results/<target>/session.json`:

   ```bash
   mkdir -p ~/pentest-toolkit/results/<target>
   ```

   ```json
   {
     "target": "<target>",
     "started": "<YYYY-MM-DD>",
     "scope": "<in-scope summary>",
     "phase": "plan",
     "ptt": {
       "nodes": [
         {"id": "root", "label": "Target: <target>", "status": "active"},
         {"id": "recon", "label": "Recon", "status": "pending", "parent": "root"},
         {"id": "secrets", "label": "Secrets", "status": "pending", "parent": "recon"},
         {"id": "exploit", "label": "Exploit", "status": "pending", "parent": "secrets"},
         {"id": "zerodayhunt", "label": "Zero-Day Hunt", "status": "optional", "parent": "exploit"},
         {"id": "oauth-attacks", "label": "OAuth Attacks", "status": "optional", "parent": "exploit"},
         {"id": "race-conditions", "label": "Race Conditions", "status": "optional", "parent": "exploit"},
         {"id": "ad-attacks", "label": "AD Attacks", "status": "optional", "parent": "exploit"},
         {"id": "triage", "label": "Triage", "status": "pending", "parent": "exploit"},
         {"id": "report", "label": "Report", "status": "pending", "parent": "triage"}
       ],
       "attack_paths": [],
       "owned_accounts": [],
       "confirmed_vulns": []
     },
     "intel": {
       "live_hosts": [],
       "open_ports": {},
       "technologies": [],
       "internal_ips": [],
       "credentials": [],
       "endpoints": []
     },
     "chains": []
   }
   ```

   **PTT Update Protocol** - every phase MUST update session.json before finishing:
   - Move completed phase node status from "pending" to "done"
   - Add discovered live_hosts, technologies, credentials to intel section
   - Add any attack chains discovered to chains array
   - Add confirmed vulns to ptt.confirmed_vulns

   **How subsequent phases use session.json:**
   ```bash
   cat ~/pentest-toolkit/results/<target>/session.json
   # Phases extract: live_hosts for targeted scanning
   #                 credentials to test live
   #                 internal_ips for SSRF target list
   #                 technologies to select relevant attack modules
   ```

5. Tell the user: "Plan saved to `~/pentest-toolkit/results/<target>/plan.md`. Session tracking initialized in `session.json`. Run `/recon <target>` to start."
