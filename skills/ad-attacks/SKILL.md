---
name: ad-attacks
description: Use when attacking Active Directory environments, hunting Kerberoastable accounts, AS-REP roasting, DCSync, Pass-the-Hash, Pass-the-Ticket, BloodHound path analysis, LDAP enumeration, GPO abuse, ACL abuse, or full AD domain compromise chains. Also use when the user says "attack AD", "domain compromise", "Kerberoast", "DCSync", "BloodHound", or "lateral movement".
---

# Active Directory Attacks - Redirect Stub

AD attack TTPs have been consolidated into the **redteam** skill, which is the canonical source for all AD, post-exploitation, lateral movement, and APT simulation techniques.

**Immediately invoke:**

```
/redteam <target> --focus=ad
```

The `--focus=ad` flag tells redteam to prioritize:
1. BloodHound collection and shortest-path analysis
2. Kerberoasting + AS-REP roasting
3. LDAP enumeration (null session -> authenticated)
4. Pass-the-Hash / Pass-the-Ticket chains
5. ADCS ESC1-ESC8 certificate abuse
6. Constrained/unconstrained delegation + RBCD
7. DCSync + DCShadow
8. GPO abuse + ACL abuse (T1484 / T1222)
9. Golden/Silver ticket forge
10. Domain compromise - NTDS.dit extraction

All techniques are documented in `~/.claude/skills/redteam/SKILL.md` under Classes RT04, RT05, RT05b, RT05c.

For full APT kill chain (C2, LotL, AMSI bypass, persistence, defense evasion, cloud APT, exfil, OPSEC) run `/redteam <target>` without the focus flag after obtaining a foothold.
