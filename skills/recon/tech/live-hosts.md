# Recon Steps 6-8: Live Host Probing + Favicon + Port Scanning

## Step 6: Live Host Probing + Technology Fingerprinting

httpx probes HTTP/HTTPS and extracts rich metadata - status codes, tech stack, screenshots, favicon hashes:

```bash
TARGET="target.com"
RESULTS=~/pentest-toolkit/results/$TARGET

httpx -l $RESULTS/recon/resolved.txt \
  -silent \
  -title -status-code -tech-detect \
  -web-server -content-length \
  -favicon \
  -jarm \
  -screenshot -srd $RESULTS/recon/screenshots \
  -json -o $RESULTS/recon/httpx-full.json \
  -threads 50 \
  -follow-redirects \
  -ports 80,443,8080,8443,8000,8001,8888,9000,9090,3000,4000,5000

# Parse httpx JSON for interesting tech + status codes
cat $RESULTS/recon/httpx-full.json | jq -r '
  select(.status_code != null) |
  "\(.status_code) | \(.url) | \(.title) | \(.tech // [] | join(","))"
' | sort -t'|' -k1 > $RESULTS/recon/live-hosts.txt

# Extract favicon hashes for Shodan/Censys hunting
cat $RESULTS/recon/httpx-full.json | \
  jq -r 'select(.favicon_mmh3 != null) | "\(.favicon_mmh3) | \(.url)"' \
  > $RESULTS/recon/favicon-hashes.txt

echo "[*] Live hosts: $(wc -l < $RESULTS/recon/live-hosts.txt)"
```

**Signal:** `emit_signal SURFACE_FOUND "Live hosts: <N> responding" "main/recon" 0.85`
**Signal:** `emit_signal TECH_DETECTED "<framework/cloud>" "main/recon" 0.80`
**Signal:** `emit_signal WAF_CONFIRMED "<waf-name> on <host>" "main/recon" 0.85`

## Step 7: Favicon Hash - Infrastructure Fingerprinting

MurmurHash3 of favicon is unique per app/framework - use it to find hidden instances, origin IPs behind CDNs:

```bash
# Extract unique favicon hashes
FAVICON_HASHES=$(cat $RESULTS/recon/favicon-hashes.txt | awk '{print $1}' | sort -u)

for HASH in $FAVICON_HASHES; do
  echo "[*] Searching favicon hash: $HASH"
  # Shodan: http.favicon.hash:$HASH
  # Censys: services.http.response.favicons.md5_hash="$HASH"
  # FOFA: icon_hash="$HASH"
  # ZoomEye: iconhash:"$HASH"
  echo "Shodan: http.favicon.hash:$HASH" >> $RESULTS/recon/favicon-hunt-queries.txt
  echo "FOFA: icon_hash=\"$HASH\"" >> $RESULTS/recon/favicon-hunt-queries.txt
done

# FavFreak - automates favicon collection and hash generation
cat $RESULTS/recon/live-hosts.txt | awk '{print $3}' | \
  python3 ~/tools/FavFreak/favfreak.py -o $RESULTS/recon/favfreak.txt 2>/dev/null

# Why: Favicons survive CDN - if 10 IPs serve same favicon hash as admin.target.com,
# one of them might be the unprotected origin.
```

## Step 8: Port Scanning

```bash
# naabu - fast port discovery
naabu -l $RESULTS/recon/resolved-ips.txt \
  -p - \
  -rate 10000 \
  -o $RESULTS/recon/naabu-ports.txt \
  -silent

# nmap - service fingerprinting on discovered ports
cat $RESULTS/recon/naabu-ports.txt | awk -F: '{print $1}' | sort -u > /tmp/scan-hosts.txt

nmap -iL /tmp/scan-hosts.txt \
  -p $(cat $RESULTS/recon/naabu-ports.txt | awk -F: '{print $2}' | sort -u | tr '\n' ',') \
  -sV -sC -O \
  --open -T4 \
  -oN $RESULTS/recon/nmap.txt \
  -oX $RESULTS/recon/nmap.xml

# masscan - for very large IP ranges from ASN discovery
if [ -s $RESULTS/recon/ip-ranges.txt ]; then
  masscan -iL $RESULTS/recon/ip-ranges.txt \
    -p 80,443,8080,8443,8000,8888,9000,9090,22,21,25,3306,5432,6379,27017 \
    --rate 50000 \
    -oJ $RESULTS/recon/masscan.json 2>/dev/null
fi

# Flag interesting ports (databases, internal services, Docker)
grep -E "3306|5432|6379|27017|9200|5601|2375|2376|4243|9000|11211|8500|8600" \
  $RESULTS/recon/nmap.txt > $RESULTS/recon/interesting-ports.txt

echo "[*] Interesting ports: $(wc -l < $RESULTS/recon/interesting-ports.txt)"
```

**Signal:** `emit_signal SURFACE_FOUND "Exposed internal service port <port> on <host>" "main/recon" 0.90`
