# Recon Step 18: Advanced Internet Scanner Queries

Beyond basic `hostname:` searches - full-text search, TLS cert mining, and cross-engine queries for maximum coverage:

```bash
TARGET="target.com"
ORG="Target Corp"
RESULTS=~/pentest-toolkit/results/$TARGET
mkdir -p $RESULTS/recon/scanners

# --- SHODAN ---
# SSL cert subject mining (finds infrastructure behind CDNs)
shodan search "ssl.cert.subject.cn:$TARGET" --fields ip_str,port,org,ssl.cert.subject.cn --limit 500 \
  > $RESULTS/recon/scanners/shodan-ssl-cert.txt

# Org name search (finds all IPs registered to org, even without target domain)
shodan search "org:\"$ORG\"" --fields ip_str,port,product,version --limit 1000 \
  >> $RESULTS/recon/scanners/shodan-org.txt

# Product/version combos for vuln prioritization
shodan search "hostname:$TARGET port:8443" --fields ip_str,port,product 2>/dev/null

# --- FOFA (Chinese scanner, massive - 10B+ assets, indexes HTML content) ---
# FOFA has unique full-text search on page content
cat << EOF >> $RESULTS/recon/scanners/fofa-queries.txt
domain="$TARGET"
cert="$TARGET"
body="$TARGET" && country="US"
icon_hash="FAVICON_HASH_FROM_STEP7"
header="X-Powered-By: TARGET_TECH"
org="$ORG"
EOF
echo "Run FOFA queries at: https://fofa.info"

# --- CENSYS ---
# Full 65k port scan data, all certificates
censys search "parsed.names: $TARGET" \
  --fields ip,protocols,parsed.subject_dn,location.country \
  --pages 10 2>/dev/null > $RESULTS/recon/scanners/censys-certs.txt

# Find all IPs with cert containing target domain (origin IP discovery)
censys search "parsed.names: $TARGET OR parsed.subject.common_name: $TARGET" \
  --fields ip,protocols 2>/dev/null | \
  awk '{print $1}' | sort -u >> $RESULTS/recon/resolved-ips.txt

# --- NETLAS (indexes domains + IPs, emphasis on DNS) ---
cat << EOF >> $RESULTS/recon/scanners/netlas-queries.txt
domain:$TARGET
host:$TARGET
certificate.subject.common_name:$TARGET
whois.org:"$ORG"
EOF
echo "Run Netlas queries at: https://netlas.io"

# --- LEAKIX (focuses on compromised/vulnerable servers) ---
curl -s "https://leakix.net/api/host?host=$TARGET" \
  -H "api-key: $LEAKIX_KEY" 2>/dev/null | \
  jq -r '.[].event_summary' | head -20 \
  > $RESULTS/recon/scanners/leakix.txt

# --- CRIMINAL IP (threat intel + scanning) ---
curl -s "https://api.criminalip.io/v1/asset/ip/report?ip=$(dig +short $TARGET | head -1)" \
  -H "x-api-key: $CRIMINALIP_KEY" 2>/dev/null | \
  jq -r '.ip_scoring, .current_opened_port.data[].port' 2>/dev/null \
  > $RESULTS/recon/scanners/criminalip.txt

# --- ZOOMEYE (Asia-focused, unique port coverage) ---
cat << EOF >> $RESULTS/recon/scanners/zoomeye-queries.txt
hostname:$TARGET
site:$TARGET
EOF
echo "Run ZoomEye queries at: https://zoomeye.org"
```

## Cross-Engine Correlation

After running all engines, correlate to find IP ranges that show up across multiple sources - these are high-confidence infrastructure IPs:

```bash
# Merge all discovered IPs
cat $RESULTS/recon/scanners/shodan-ssl-cert.txt \
    $RESULTS/recon/scanners/shodan-org.txt \
    $RESULTS/recon/scanners/censys-certs.txt \
    2>/dev/null | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" | sort | uniq -c | sort -rn \
    > $RESULTS/recon/scanners/ip-frequency.txt

# IPs appearing in 3+ sources = confirmed infrastructure
awk '$1 >= 3 {print $2}' $RESULTS/recon/scanners/ip-frequency.txt \
  >> $RESULTS/recon/resolved-ips.txt

echo "[*] High-confidence IPs (3+ scanner sources): $(awk '$1 >= 3' $RESULTS/recon/scanners/ip-frequency.txt | wc -l)"
```
