---
name: redteam
description: Use when running APT-level red team operations, post-exploitation, lateral movement, credential harvesting, Active Directory attacks (Kerberoasting, DCSync, Golden/Silver tickets, ADCS ESC chains, BloodHound), C2 framework tradecraft (Cobalt Strike, Havoc, Sliver), Living off the Land binaries, defense evasion (AMSI bypass, ETW patching, process hollowing), persistence, cloud APT (Azure AD Pass-the-PRT, Device Code phishing, ADFS Golden SAML, AWS assumed-role lateral movement), data exfiltration, or OPSEC tradecraft. Also triggers on "red team", "APT simulation", "post-exploitation", "lateral movement", "persistence", "AD attacks", "C2", "LotL", "Living off the Land", "BloodHound", "Kerberoast", "DCSync", "ADCS", "credential harvesting", "defense evasion", "domain fronting".
---

# Red Team / APT Simulation Phase

## Philosophy

APT simulation is not about running a tool and reporting output. It is about proving a complete kill chain - initial foothold to Crown Jewels. Every technique in this skill is used in authorized red team engagements, documented in MITRE ATT&CK, and referenced in Mandiant/CrowdStrike/Recorded Future adversary reports.

This skill activates after a foothold is established (exploit phase proved initial access) or from an assumed-breach scenario. Every technique requires written authorization scope.

---

## Phase 0: Smart Intake

```bash
source ~/.claude/skills/_shared/phase0.sh
source ~/.claude/skills/_shared/signals.sh

p0_init_vars "$1"
p0_state_gate || exit 0

p0_read_relay exploit secrets recon cloud_audit
p0_read_memory

TECH_STACK=$(jq -r '.intel.technologies[]?' "$SESSION" 2>/dev/null | tr '\n' ',')

echo "=== REDTEAM SMART INTAKE: $TARGET ==="
echo "State: $STATE | Tech: $TECH_STACK"
echo "Confirmed vulns: $(echo "$CONFIRMED_VULNS" | grep -c .)"
echo "Internal IPs reachable: $(echo "$INTERNAL_IPS" | grep -c .)"
echo "Verified creds: $(echo "$VERIFIED_CREDS" | grep -c .)"
echo "Auth bypass confirmed: $VERIFIED_AUTH_BYPASS"
echo "ATW flagged (skip): $ATW_FLAGGED"
```

**Intake-to-technique priority:**

| Signal available | Prioritize |
|---|---|
| Internal IPs + SSRF vector | C2 setup -> lateral movement |
| AD/LDAP/Kerberos in tech stack | BloodHound -> Kerberoast -> DCSync |
| AWS keys in secrets relay | Assumed-role lateral movement -> S3/RDS |
| Azure AD hint | Device Code phishing -> Pass-the-PRT -> ADFS |
| Confirmed auth bypass | Assumed breach - skip initial access |
| Windows hosts reachable | Credential harvesting -> Pass-the-Hash |
| Linux pivot available | SUID/sudo -> cron hijack -> kernel exploits |

---

## Phase 1: Build Execution Manifest

```bash
MANIFEST_ITEMS="[]"

[ "$VERIFIED_AUTH_BYPASS" = "false" ] && \
  MANIFEST_ITEMS=$(echo $MANIFEST_ITEMS | jq '. + [{"id":"rt01","tool":"initial_access","priority":"MUST","status":"pending"}]')

MANIFEST_ITEMS=$(echo $MANIFEST_ITEMS | jq '. + [{"id":"rt02","tool":"c2_setup","priority":"MUST","status":"pending"}]')
MANIFEST_ITEMS=$(echo $MANIFEST_ITEMS | jq '. + [{"id":"rt03","tool":"cred_harvest","priority":"MUST","status":"pending"}]')

echo "$TECH_STACK" | grep -qi "ldap\|kerberos\|active.directory\|domain" && \
  MANIFEST_ITEMS=$(echo $MANIFEST_ITEMS | jq '. + [{"id":"rt04","tool":"ad_attacks","priority":"MUST","status":"pending"}]')

[ -n "$INTERNAL_IPS" ] && \
  MANIFEST_ITEMS=$(echo $MANIFEST_ITEMS | jq '. + [{"id":"rt05","tool":"lateral_movement","priority":"MUST","status":"pending"}]')

echo "$TECH_STACK" | grep -qi "aws\|azure\|gcp\|cloud" && \
  MANIFEST_ITEMS=$(echo $MANIFEST_ITEMS | jq '. + [{"id":"rt06","tool":"cloud_apt","priority":"MUST","status":"pending"}]')

MANIFEST_ITEMS=$(echo $MANIFEST_ITEMS | jq '. + [{"id":"rt07","tool":"persistence","priority":"SHOULD","status":"pending"}]')
MANIFEST_ITEMS=$(echo $MANIFEST_ITEMS | jq '. + [{"id":"rt08","tool":"defense_evasion","priority":"SHOULD","status":"pending"}]')
MANIFEST_ITEMS=$(echo $MANIFEST_ITEMS | jq '. + [{"id":"rt09","tool":"data_exfil","priority":"SHOULD","status":"pending"}]')
MANIFEST_ITEMS=$(echo $MANIFEST_ITEMS | jq '. + [{"id":"rt10","tool":"opsec","priority":"IF_TIME","status":"pending"}]')

p0_manifest_write "redteam" "$MANIFEST_ITEMS"
```

---

## Phase 2: Technique Loader

**Read ONLY the technique files that match your active manifest items.**

Use the `Read` tool: `~/.claude/skills/redteam/tech/<filename>`

| Manifest ID / focus flag | Technique file | Load when |
|---|---|---|
| rt01 - initial access | `initial-access.md` | no auth bypass confirmed |
| rt02 - C2 framework | `c2.md` | always |
| rt03 - cred harvest | `creds.md` | always |
| rt04 - AD attacks | `ad-core.md` | AD/LDAP/Kerberos in tech |
| rt04 (ADCS) | `adcs.md` | AD confirmed + ADCS endpoint found |
| rt04 (delegation) | `delegation.md` | AD confirmed + delegation flags found |
| rt04 (GPO/ACL) | `gpo-acl.md` | BloodHound path involves GPO/ACL |
| rt05 - lateral movement | `lateral.md` | internal IPs reachable |
| rt05 (LotL) | `lotl.md` | Windows hosts confirmed |
| rt06 - cloud APT | `cloud-apt.md` | cloud hints in tech stack |
| rt07 - persistence | `persistence.md` | foothold established |
| rt08 - defense evasion | `evasion.md` | AV/EDR present |
| rt09 - data exfil | `exfil.md` | Crown Jewels located |
| rt10 - OPSEC | `opsec.md` | all IF_TIME |

**Focus flag routing (`--focus=ad` etc.):**

| Focus flag | Load these files |
|---|---|
| `--focus=ad` | `ad-core.md`, `adcs.md`, `delegation.md`, `gpo-acl.md` |
| `--focus=cloud` | `cloud-apt.md` |
| `--focus=evasion` | `evasion.md`, `c2.md` |
| `--focus=initial` | `initial-access.md` |
| `--focus=lateral` | `lateral.md`, `lotl.md`, `creds.md` |

**Available technique files in `redteam/tech/`:**

| File | Covers |
|---|---|
| `initial-access.md` | HTML smuggling, macro-less Office, LNK/ISO, drive-by, fake CAPTCHA |
| `c2.md` | Cobalt Strike malleable profiles, Havoc, Sliver, domain fronting |
| `lotl.md` | LOLBins, LOLDrivers, LSASS without Mimikatz, certutil/mshta/regsvr32 |
| `creds.md` | LSASS dump, DCSync, SAM, DPAPI, Kerberos ticket extraction |
| `ad-core.md` | BloodHound, Kerberoasting, AS-REP, PTH, PTT, Golden/Silver tickets |
| `adcs.md` | ADCS ESC1-ESC8, certipy workflow, certificate-based persistence |
| `delegation.md` | Constrained/unconstrained delegation, RBCD, S4U2Self/S4U2Proxy |
| `gpo-acl.md` | GPO abuse (T1484.001), ACL abuse chains (T1222), DCShadow |
| `lateral.md` | WMI exec, PSExec, DCOM, WinRM, SMB relay, MSSQL xp_cmdshell |
| `persistence.md` | Registry Run keys, WMI subscriptions, scheduled tasks, DLL hijack |
| `evasion.md` | AMSI/ETW bypass, process hollowing, reflective DLL, indirect syscalls |
| `cloud-apt.md` | Azure Device Code phishing, Pass-the-PRT, ADFS Golden SAML, AWS/GCP lateral |
| `exfil.md` | DNS exfil, HTTPS beaconing, cloud storage staging, encrypted channels |
| `opsec.md` | PPID spoofing, timestomping, log clearing, network noise reduction |

---

## Phase 3: Core Workflow

1. Load only the technique files your manifest requires.
2. Execute each technique. Mark done: `p0_mark_done rt0X`.
3. For every confirmed technique, write to `report_draft.findings[]` and emit signal.
4. Run completion gate: `p0_completion_gate || echo "GATE BLOCKED"`

**Phase-End - Intel Relay write + interesting_redteam.md:**

```bash
# Write intel relay
jq --arg dacreds "${DA_CREDENTIALS:-}" \
   --arg killchain "${CONFIRMED_KILL_CHAIN:-}" \
   --argjson pthhosts "$(echo "${LATERAL_TARGETS:-}" | tr ',' '\n' | jq -R . | jq -s .)" \
'.intel_relay.from_redteam = {
  "da_credentials_obtained": ($dacreds != ""),
  "da_credentials": $dacreds,
  "lateral_movement_hosts": $pthhosts,
  "kill_chain": $killchain,
  "privesc_confirmed": true,
  "persistence_confirmed": true,
  "techniques_used": [.report_draft.findings[] | select(.phase=="redteam") | .technique],
  "evasion_techniques": [],
  "exfil_confirmed": false
}' $SESSION > /tmp/s.json && mv /tmp/s.json $SESSION

# Write interesting_redteam.md
cat > $RESULTS/interesting_redteam.md << EOF
# Red Team Findings: $TARGET
Generated: $(date +%Y-%m-%d)

## Kill Chain
${CONFIRMED_KILL_CHAIN:-TBD}

## Techniques Confirmed
$(jq -r '.report_draft.findings[] | select(.phase=="redteam") | "- [\(.severity)] \(.title)"' $SESSION 2>/dev/null)

## DA Credentials
$(jq -r '.intel_relay.from_redteam.da_credentials // "none"' $SESSION 2>/dev/null)

## Lateral Movement Hosts
$(jq -r '.intel_relay.from_redteam.lateral_movement_hosts[]?' $SESSION 2>/dev/null)

## Evidence
$(ls $LOOT/ 2>/dev/null | head -20)
EOF

echo "Next: /triage $TARGET"
```

---

## Quick Reference: Tool Matrix

| Technique | Windows Tool | Linux/Remote Tool | MITRE ID |
|---|---|---|---|
| BloodHound collection | SharpHound.exe | bloodhound-python | T1482 |
| Kerberoasting | Rubeus kerberoast | GetUserSPNs.py | T1558.003 |
| AS-REP Roasting | Rubeus asreproast | GetNPUsers.py | T1558.004 |
| DCSync | mimikatz dcsync | secretsdump.py | T1003.006 |
| Pass-the-Hash | mimikatz sekurlsa::pth | crackmapexec -H | T1550.002 |
| Golden Ticket | mimikatz kerberos::golden | ticketer.py | T1558.001 |
| ADCS ESC1 | Certify.exe | certipy req | T1649 |
| LSASS dump | comsvcs MiniDump | procdump | T1003.001 |
| Lateral WMI | Invoke-WmiMethod | wmiexec.py | T1047 |
| Lateral WinRM | Enter-PSSession | evil-winrm | T1021.006 |
| AMSI bypass | memory patch PS | N/A | T1562.001 |
| Process hollow | C# CreateProcess | N/A | T1055.012 |
| DNS exfil | dnscat2 client | dnscat2 server | T1071.004 |
| Device Code phish | N/A | device_code_phish.py | T1528 |
| ADFS Golden SAML | AADInternals | shimit | T1606.002 |
