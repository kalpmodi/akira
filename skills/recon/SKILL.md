---
name: recon
description: Use when running reconnaissance on a pentest target, starting phase 1 of an engagement, gathering subdomains, DNS resolution, live hosts, port scan results, or URL intelligence. Also use when the user says "run recon", "start recon", or "phase 1".
---

# Recon Phase

## Overview
Runs the recon toolkit against a target and summarizes key findings into `interesting_recon.md` for downstream phases to consume.

## Steps

1. **Get target** from user if not provided.

2. **Check for plan.md** (optional):
   ```bash
   cat ~/pentest-toolkit/results/<target>/plan.md 2>/dev/null
   ```
   If present, note any custom flags or exclusions mentioned.

3. **Run recon:**
   ```bash
   ~/pentest-toolkit/recon/recon.sh <target>
   ```
   If exit code is non-zero: stop, invoke `superpowers:systematic-debugging` to diagnose the failure before continuing.

4. **Check for empty output:**
   ```bash
   wc -l ~/pentest-toolkit/results/<target>/recon/resolved.txt 2>/dev/null
   wc -l ~/pentest-toolkit/results/<target>/recon/live-hosts.txt 2>/dev/null
   ```
   If both are empty or missing: write `interesting_recon.md` with `## Status` = `no-findings` and warn the user.

5. **Read and summarize results:**
   ```bash
   cat ~/pentest-toolkit/results/<target>/recon/subdomains.txt
   cat ~/pentest-toolkit/results/<target>/recon/live-hosts.txt
   cat ~/pentest-toolkit/results/<target>/recon/nmap.txt
   ```

6. **Write `interesting_recon.md`** to `~/pentest-toolkit/results/<target>/interesting_recon.md` using this schema:

```markdown
## Status
findings-present

## Summary
<one paragraph: how many subdomains found, how many live hosts, notable open ports>

## Key Findings
- [CONFIRMED] <subdomain> — live host, ports: <list>
- [POTENTIAL] <subdomain> — resolved but not probed

## Raw Evidence References
- ~/pentest-toolkit/results/<target>/recon/subdomains.txt
- ~/pentest-toolkit/results/<target>/recon/live-hosts.txt
- ~/pentest-toolkit/results/<target>/recon/nmap.txt
```

7. **Update session.json** with discovered intel:
   ```bash
   # Read current session.json, then update it:
   cat ~/pentest-toolkit/results/<target>/session.json 2>/dev/null
   ```
   Write back session.json with:
   - `intel.live_hosts`: list of hosts from live-hosts.txt
   - `intel.open_ports`: dict of host -> [port list] from nmap.txt
   - `intel.technologies`: list of tech stack items from httpx/whatweb output
   - `ptt.nodes`: mark "recon" node status = "done"

8. Tell the user: "Recon complete. `interesting_recon.md` written. Session intel updated. Run `/secrets <target>` for phase 2."
