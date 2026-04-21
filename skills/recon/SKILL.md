---
name: recon
description: Use when running reconnaissance on a pentest target, starting phase 1 of an engagement, gathering subdomains, DNS resolution, live hosts, port scan results, URL intelligence, JavaScript endpoints, GitHub secrets, cloud buckets, subdomain takeovers, or attack surface mapping. Also use when the user says "run recon", "start recon", "phase 1", "enumerate subdomains", "find attack surface", or "map the target".
---

# Recon Phase

## Overview

Reconnaissance is the most important phase - the attack surface you find here directly determines what you can exploit. Thin recon = missed bugs. This skill runs 23 layers of discovery: passive subdomain sources, certificate transparency mining, active brute-force + permutation, DNS resolution, live host probing, port scanning, favicon fingerprinting, URL archive mining, JS analysis, GitHub dorking, cloud bucket discovery, subdomain takeover detection, AXFR zone transfer, DNSSEC NSEC zone walking, passive DNS historical intelligence, advanced scanner queries (FOFA/Netlas/LeakIX/Criminal IP), JARM/JA4+ TLS fingerprinting, supply chain dependency confusion recon, Wayback CDX advanced mining, and reconFTW orchestration.

**Goal:** Build a complete picture of the target's attack surface - every subdomain, IP, port, endpoint, and technology - then write `interesting_recon.md` for downstream phases.

---

## Session Intelligence Protocol

Read session.json before running any step. This determines what to skip, what to prioritize, and what signals to emit.

```bash
SESSION=~/pentest-toolkit/results/<target>/session.json
STATE=$(cat $SESSION 2>/dev/null | jq -r '.engagement_state // "WIDE"')
HYPS=$(cat $SESSION 2>/dev/null | jq -r '.hypotheses[] | select(.status=="active") | "\(.id)[\((.probability * 100)|round)%] \(.label)"' 2>/dev/null)
KNOWN_TECH=$(cat $SESSION 2>/dev/null | jq -r '.intel.technologies[]?' 2>/dev/null | tr '\n' ',')
echo "State: $STATE | Tech already known: $KNOWN_TECH"
echo "Active hypotheses: $HYPS"
```

**State machine check - do this first:**
- `WIDE` → run full 23-step pipeline (standard flow)
- `DEEP` → skip Steps 2-5 (subdomain discovery). Run only Steps 6, 8, 15, 18, 19 targeted at the active hypothesis chain surface.
- `HARVEST` → skip recon entirely. The engagement is in evidence extraction mode.

**Hypothesis-driven step ordering:**

Before running steps, check hypotheses and reorder execution to confirm/deny them first:

| Hypothesis mentions | Prioritize these steps first |
|---|---|
| AWS / GCP / Azure / cloud | 12, 18, 19 (cloud assets, scanners, JARM) |
| JWT / OAuth / SSO | 10, 11 (JS analysis, GitHub dorking) |
| Supply chain / dependency | 20 (dependency confusion) |
| SSRF / internal IP | 8, 18 (port scan, scanner queries) |
| Subdomain takeover | 13 (takeover detection) |
| No specific hypothesis | Run Steps 1-22 in order |

**Signal emission - emit these signals throughout the steps:**

| Discovery point | Signal to emit | When |
|---|---|---|
| Step 2-4: new subdomains | `SURFACE_FOUND` | After merge, emit for significant batches |
| Step 6: live hosts | `SURFACE_FOUND` | Each live host found |
| Step 6: tech detected | `TECH_DETECTED` | Each framework/cloud provider |
| Step 6: WAF header/fingerprint | `WAF_CONFIRMED` | When WAF identified |
| Step 8: unusual open ports | `SURFACE_FOUND` | DB ports, internal services exposed |
| Step 11: verified GitHub secret | `CRED_FOUND` | Immediately on TruffleHog verified hit |
| Step 12: open cloud bucket | `SURFACE_FOUND` | Each accessible bucket |
| Step 16a: AXFR success | `SURFACE_FOUND` | Entire zone dump - critical, emit immediately |
| Step 20: unclaimed npm/pypi | `SURFACE_FOUND` | Each unclaimed package (type: supply_chain) |

After every `TECH_DETECTED` signal, check correlation rules in plan-engagement Step 6 - tech signals may immediately activate modules or boost hypotheses.

See `~/.claude/skills/plan-engagement/references/fork-protocol.md` for signal format and emission protocol.

---

## Step 1: Setup + ASN/IP Range Mapping

Start wide - map the organization's entire IP space, not just the given domain. Shadow assets often live on IP ranges not connected to the main domain.

```bash
TARGET="target.com"
ORG="Target Corp"   # adjust to org name as it appears in WHOIS/ARIN
RESULTS=~/pentest-toolkit/results/$TARGET
mkdir -p $RESULTS/recon

# ASN lookup - find all IP ranges owned by the organization
# asnmap: https://github.com/projectdiscovery/asnmap
echo "$ORG" | asnmap -json 2>/dev/null | tee $RESULTS/recon/asn.json
# Also query bgp.he.net manually: https://bgp.he.net/search?search[search]=$ORG

# Extract CIDR ranges for later scanning
cat $RESULTS/recon/asn.json | jq -r '.[] | .cidr[]?' 2>/dev/null > $RESULTS/recon/ip-ranges.txt

# WHOIS for registration data and org contacts
whois $TARGET | tee $RESULTS/recon/whois.txt
whois -h whois.arin.net "n $ORG" 2>/dev/null | grep -i "CIDR\|NetRange" | tee -a $RESULTS/recon/ip-ranges.txt

echo "[*] IP ranges found: $(wc -l < $RESULTS/recon/ip-ranges.txt)"
```

---

## Step 2: Passive Subdomain Enumeration (Multi-Source)

Query as many passive sources as possible - each source finds subdomains others miss:

```bash
TARGET="target.com"
RESULTS=~/pentest-toolkit/results/$TARGET

# Subfinder - queries 40+ passive sources (CT logs, DNS DBs, search engines)
subfinder -d $TARGET -all -recursive -o $RESULTS/recon/subfinder.txt -silent

# Amass passive - CAIDA, ARIN, BGP, DNS, ThreatCrowd, etc.
amass enum -passive -d $TARGET -o $RESULTS/recon/amass.txt -config ~/.config/amass/config.yaml 2>/dev/null

# Assetfinder - Certspotter + Hackertarget + Facebook CT + crt.sh
assetfinder --subs-only $TARGET | tee $RESULTS/recon/assetfinder.txt

# Chaos (ProjectDiscovery) - pre-indexed bug bounty program data
# https://chaos.projectdiscovery.io - requires API key
chaos -d $TARGET -silent -key $CHAOS_KEY 2>/dev/null | tee $RESULTS/recon/chaos.txt

# Merge and deduplicate all passive sources
cat $RESULTS/recon/subfinder.txt \
    $RESULTS/recon/amass.txt \
    $RESULTS/recon/assetfinder.txt \
    $RESULTS/recon/chaos.txt \
    2>/dev/null | sort -u > $RESULTS/recon/passive-all.txt

echo "[*] Unique passive subdomains: $(wc -l < $RESULTS/recon/passive-all.txt)"
```

---

## Step 3: Certificate Transparency Deep Mining

CT logs are comprehensive - every certificate ever issued is logged. The PostgreSQL API on crt.sh allows deeper queries than the web UI:

```bash
TARGET="target.com"
RESULTS=~/pentest-toolkit/results/$TARGET

# crt.sh - wildcard query picks up all subdomains including *.subdomain.target.com
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" 2>/dev/null | \
  jq -r '.[].name_value' | \
  sed 's/\*\.//g' | \
  grep -v "^$" | \
  sort -u > $RESULTS/recon/crt-sh.txt

# crt.sh PostgreSQL API (faster, more results, supports advanced queries)
psql -h crt.sh -U guest certwatch 2>/dev/null << 'EOF'
SELECT DISTINCT ci.NAME_VALUE
FROM certificate_identity ci
JOIN certificate c ON c.id = ci.certificate_id
JOIN ca ON ca.id = c.issuer_ca_id
WHERE ci.NAME_TYPE = 'dNSName'
  AND ci.NAME_VALUE ILIKE '%target.com'
  AND x509_notAfter(c.certificate) > NOW() - INTERVAL '5 years';
EOF

# Mine expired/revoked certs too - they reveal decommissioned assets that may still be up
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" 2>/dev/null | \
  jq -r '.[].name_value' | sort -u >> $RESULTS/recon/crt-sh.txt

# Certspotter - different log sources than crt.sh
curl -s "https://api.certspotter.com/v1/issuances?domain=$TARGET&include_subdomains=true&expand=dns_names" \
  -H "Authorization: Bearer $CERTSPOTTER_KEY" 2>/dev/null | \
  jq -r '.[].dns_names[]' | sort -u | tee $RESULTS/recon/certspotter.txt

cat $RESULTS/recon/crt-sh.txt $RESULTS/recon/certspotter.txt | sort -u >> $RESULTS/recon/passive-all.txt
sort -u $RESULTS/recon/passive-all.txt -o $RESULTS/recon/passive-all.txt

echo "[*] After CT mining: $(wc -l < $RESULTS/recon/passive-all.txt) unique subdomains"
```

---

## Step 4: Active Subdomain Brute-Force + Permutation

Passive sources miss internal names and recently added subdomains. Brute-force with quality wordlists and permutation-based discovery catches these:

```bash
TARGET="target.com"
RESULTS=~/pentest-toolkit/results/$TARGET

# puredns - DNS brute-force with wildcard detection (uses massdns under the hood)
# Best wordlists: SecLists + assetnote
puredns bruteforce \
  /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  $TARGET \
  --resolvers ~/pentest-toolkit/wordlists/resolvers.txt \
  --write $RESULTS/recon/puredns-brute.txt \
  --write-wildcards $RESULTS/recon/wildcards.txt

# Permutation/alteration - generates variants from known subdomains
# dnsgen creates: api-dev, api-staging, api2, api-v2, api-prod, etc.
cat $RESULTS/recon/passive-all.txt | dnsgen - | \
  puredns resolve --resolvers ~/pentest-toolkit/wordlists/resolvers.txt \
  --write $RESULTS/recon/dnsgen-resolved.txt

# gotator - more aggressive permutation (prefixes, suffixes, swaps)
gotator -sub $RESULTS/recon/passive-all.txt \
  -perm ~/pentest-toolkit/wordlists/gotator-perms.txt \
  -depth 1 -numbers 3 -md -prefixes -adv 2>/dev/null | \
  puredns resolve --resolvers ~/pentest-toolkit/wordlists/resolvers.txt \
  --write $RESULTS/recon/gotator-resolved.txt

# Merge all active results
cat $RESULTS/recon/puredns-brute.txt \
    $RESULTS/recon/dnsgen-resolved.txt \
    $RESULTS/recon/gotator-resolved.txt \
    $RESULTS/recon/passive-all.txt \
    2>/dev/null | sort -u > $RESULTS/recon/all-subdomains.txt

echo "[*] Total unique subdomains: $(wc -l < $RESULTS/recon/all-subdomains.txt)"
```

---

## Step 5: DNS Resolution + Wildcard Detection

Resolve all found subdomains to IPs. Filter wildcards - they fake-positive all DNS queries:

```bash
TARGET="target.com"
RESULTS=~/pentest-toolkit/results/$TARGET

# puredns resolve - mass DNS resolution with wildcard detection
puredns resolve $RESULTS/recon/all-subdomains.txt \
  --resolvers ~/pentest-toolkit/wordlists/resolvers.txt \
  --write $RESULTS/recon/resolved.txt \
  --write-wildcards $RESULTS/recon/wildcards.txt \
  --rate-limit 3000

# Extract IPs from resolved hosts (for port scanning)
cat $RESULTS/recon/resolved.txt | \
  dnsx -silent -a -resp-only 2>/dev/null | sort -u > $RESULTS/recon/resolved-ips.txt

# dnsx - get full DNS records (A, CNAME, MX, NS, TXT, SOA)
# CNAME chains often point to takeover-able services
dnsx -l $RESULTS/recon/all-subdomains.txt \
  -a -cname -mx -ns -txt -resp \
  -o $RESULTS/recon/dns-records.txt -silent

# Extract CNAMEs pointing to third-party services (potential takeovers)
grep "CNAME" $RESULTS/recon/dns-records.txt | \
  grep -i "github\|heroku\|amazonaws\|azurewebsites\|cloudfront\|shopify\|zendesk\|wordpress\|fastly" \
  > $RESULTS/recon/potential-takeovers.txt

echo "[*] Resolved: $(wc -l < $RESULTS/recon/resolved.txt)"
echo "[*] Potential takeovers: $(wc -l < $RESULTS/recon/potential-takeovers.txt)"
```

---

## Step 6: Live Host Probing + Technology Fingerprinting

Not all resolved hosts have web servers. httpx probes HTTP/HTTPS and extracts rich metadata:

```bash
TARGET="target.com"
RESULTS=~/pentest-toolkit/results/$TARGET

# httpx - HTTP probing with full tech fingerprinting
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

---

## Step 7: Favicon Hash - Infrastructure Fingerprinting

**Source:** "Weaponizing favicon.ico" research. MurmurHash3 of favicon is unique per app/framework - use it to find hidden instances, origin IPs behind CDNs, and related infrastructure.

```bash
TARGET="target.com"
RESULTS=~/pentest-toolkit/results/$TARGET

# Extract unique favicon hashes
FAVICON_HASHES=$(cat $RESULTS/recon/favicon-hashes.txt | awk '{print $1}' | sort -u)

for HASH in $FAVICON_HASHES; do
  echo "[*] Searching favicon hash: $HASH"

  # Shodan query - finds all IPs serving same favicon (bypasses CDN)
  echo "Shodan: http.favicon.hash:$HASH"

  # Censys query
  echo "Censys: services.http.response.favicons.md5_hash=\"$HASH\""

  # FOFA query (Chinese search engine, massive IoT index)
  echo "FOFA: icon_hash=\"$HASH\""

  # ZoomEye
  echo "ZoomEye: iconhash:\"$HASH\""
done > $RESULTS/recon/favicon-hunt-queries.txt

cat $RESULTS/recon/favicon-hunt-queries.txt

# FavFreak - automates favicon collection and hash generation
# https://github.com/devanshbatham/FavFreak
cat $RESULTS/recon/live-hosts.txt | awk '{print $3}' | \
  python3 ~/tools/FavFreak/favfreak.py -o $RESULTS/recon/favfreak.txt 2>/dev/null
```

**Why this matters:** Favicons survive CDN/WAF bypass attempts - if 10 IPs serve the same favicon hash as admin.target.com, one of them might be the unprotected origin.

---

## Step 8: Port Scanning

```bash
TARGET="target.com"
RESULTS=~/pentest-toolkit/results/$TARGET

# naabu - fast port discovery (ProjectDiscovery, handles rate limiting well)
naabu -l $RESULTS/recon/resolved-ips.txt \
  -p - \                         # all 65535 ports
  -rate 10000 \
  -o $RESULTS/recon/naabu-ports.txt \
  -silent

# nmap - service fingerprinting on discovered ports
# Parse naabu output to nmap format
cat $RESULTS/recon/naabu-ports.txt | \
  awk -F: '{print $1}' | sort -u > /tmp/scan-hosts.txt

nmap -iL /tmp/scan-hosts.txt \
  -p $(cat $RESULTS/recon/naabu-ports.txt | awk -F: '{print $2}' | sort -u | tr '\n' ',') \
  -sV -sC -O \
  --open \
  -T4 \
  -oN $RESULTS/recon/nmap.txt \
  -oX $RESULTS/recon/nmap.xml

# masscan - for very large IP ranges from ASN discovery
if [ -s $RESULTS/recon/ip-ranges.txt ]; then
  masscan -iL $RESULTS/recon/ip-ranges.txt \
    -p 80,443,8080,8443,8000,8888,9000,9090,22,21,25,3306,5432,6379,27017 \
    --rate 50000 \
    -oJ $RESULTS/recon/masscan.json 2>/dev/null
fi

# Flag interesting ports
grep -E "3306|5432|6379|27017|9200|5601|2375|2376|4243|9000|11211|8500|8600" \
  $RESULTS/recon/nmap.txt > $RESULTS/recon/interesting-ports.txt
```

---

## Step 9: URL Discovery - Archive Mining + Live Crawl

Historical URLs reveal endpoints, parameters, and old functionality that still exists in the backend but isn't linked:

```bash
TARGET="target.com"
RESULTS=~/pentest-toolkit/results/$TARGET
mkdir -p $RESULTS/recon/urls

# gau - fetches ALL known URLs from Wayback, Common Crawl, OTX, URLScan
gau --threads 10 --subs $TARGET | tee $RESULTS/recon/urls/gau.txt

# waymore - more aggressive archive mining (multiple sources + filters)
waymore -i $TARGET -mode U -oU $RESULTS/recon/urls/waymore.txt 2>/dev/null

# katana - active JS-aware crawler (finds endpoints dynamically loaded)
katana -list $RESULTS/recon/live-hosts.txt \
  -jc \                  # JS crawling - parses JavaScript files
  -d 5 \                 # depth 5
  -aff \                 # auto-form fill
  -kf robotstxt,sitemapxml \
  -o $RESULTS/recon/urls/katana.txt \
  -silent

# Merge and filter for interesting paths
cat $RESULTS/recon/urls/gau.txt \
    $RESULTS/recon/urls/waymore.txt \
    $RESULTS/recon/urls/katana.txt \
    2>/dev/null | sort -u > $RESULTS/recon/urls/all-urls.txt

# Separate interesting URLs (params, admin paths, APIs, config files)
grep -iE "admin|config|backup|\.env|\.git|api/|internal|swagger|graphql|upload|debug|test|dev|staging|\?.*=" \
  $RESULTS/recon/urls/all-urls.txt | sort -u > $RESULTS/recon/urls/interesting-urls.txt

echo "[*] Total URLs: $(wc -l < $RESULTS/recon/urls/all-urls.txt)"
echo "[*] Interesting URLs: $(wc -l < $RESULTS/recon/urls/interesting-urls.txt)"
```

---

## Step 10: JavaScript Analysis - Endpoint + Secret Extraction

JS files are goldmines. They contain hardcoded API keys, internal endpoints, auth tokens, and GraphQL schemas that aren't visible from the surface:

```bash
TARGET="target.com"
RESULTS=~/pentest-toolkit/results/$TARGET
mkdir -p $RESULTS/recon/js

# Extract all JS file URLs from discovered URLs
grep "\.js$\|\.js?" $RESULTS/recon/urls/all-urls.txt | sort -u > $RESULTS/recon/js/js-urls.txt

# Download all JS files
mkdir -p $RESULTS/recon/js/files
cat $RESULTS/recon/js/js-urls.txt | while read URL; do
  FILENAME=$(echo $URL | md5sum | cut -d' ' -f1).js
  curl -sk "$URL" -o "$RESULTS/recon/js/files/$FILENAME" 2>/dev/null
  echo "$URL -> $FILENAME" >> $RESULTS/recon/js/url-map.txt
done

# LinkFinder - extract endpoints and paths from JS
# https://github.com/GerbenJavado/LinkFinder
cat $RESULTS/recon/js/js-urls.txt | while read URL; do
  python3 ~/tools/LinkFinder/linkfinder.py -i "$URL" -o cli 2>/dev/null
done | sort -u | tee $RESULTS/recon/js/linkfinder-endpoints.txt

# SecretFinder - API keys, tokens, credentials in JS
python3 ~/tools/SecretFinder/SecretFinder.py \
  -i $RESULTS/recon/js/files/ \
  -o $RESULTS/recon/js/secrets.txt 2>/dev/null

# TruffleHog JS scan
trufflehog filesystem $RESULTS/recon/js/files/ \
  --only-verified \
  --json 2>/dev/null | tee $RESULTS/recon/js/trufflehog-js.json

# nuclei JS analysis templates
nuclei -l $RESULTS/recon/js/js-urls.txt \
  -t ~/nuclei-templates/exposures/tokens/ \
  -t ~/nuclei-templates/exposures/apis/ \
  -json -o $RESULTS/recon/js/nuclei-js.json -silent

# Mine Wayback Machine for OLD JS versions (often contain deleted secrets)
cat $RESULTS/recon/js/js-urls.txt | while read URL; do
  DOMAIN=$(echo $URL | awk -F/ '{print $3}')
  curl -s "https://web.archive.org/cdx/search/cdx?url=$URL&output=json&fl=timestamp,original&limit=5" 2>/dev/null | \
    jq -r '.[] | "https://web.archive.org/web/\(.[0])/\(.[1])"'
done | sort -u > $RESULTS/recon/js/wayback-js-urls.txt

echo "[*] JS files analyzed: $(ls $RESULTS/recon/js/files/ | wc -l)"
echo "[*] Endpoints found: $(wc -l < $RESULTS/recon/js/linkfinder-endpoints.txt)"
```

---

## Step 11: GitHub / GitLab Dorking + Secret Scanning

In 2024, 23.8 million secrets were leaked on GitHub - 39 million total across the platform. Orgs accidentally push API keys, internal hostnames, and credentials to public repos constantly:

```bash
TARGET="target.com"
ORG="targetorg"   # GitHub org name
RESULTS=~/pentest-toolkit/results/$TARGET
mkdir -p $RESULTS/recon/github

# TruffleHog - scan entire GitHub organization for verified secrets
# Verified = TruffleHog actually tested the credential against the API
trufflehog github \
  --org=$ORG \
  --only-verified \
  --json 2>/dev/null | tee $RESULTS/recon/github/trufflehog-org.json

# Scan for deleted commits / force-pushed history (GitHub keeps these)
trufflehog github \
  --org=$ORG \
  --include-unverified \
  --since-commit HEAD~1000 \
  --json 2>/dev/null | tee $RESULTS/recon/github/trufflehog-history.json

# GitLeaks - fast regex-based scanning for common secret patterns
gitleaks detect \
  --source=$RESULTS/recon/github/ \
  -v --report-format json \
  --report-path=$RESULTS/recon/github/gitleaks.json 2>/dev/null

# Manual GitHub dorks (search these at github.com/search)
cat << EOF > $RESULTS/recon/github/dorks.txt
# Secrets
"$TARGET" password
"$TARGET" api_key
"$TARGET" secret_key
"$TARGET" token
"$TARGET" credentials
"$TARGET" "-----BEGIN RSA PRIVATE KEY-----"
"$TARGET" aws_access_key_id
"$TARGET" "AKIA" OR "ASIA"

# Internal infrastructure
"$TARGET" internal hostname
"$TARGET" staging dev
"$TARGET" jdbc:// OR mongodb:// OR postgres://

# Config files
"$TARGET" filename:.env
"$TARGET" filename:config.yaml OR filename:config.json
"$TARGET" filename:docker-compose.yml

# Source code
"$TARGET" language:python OR language:javascript
"@$TARGET" email
EOF

echo "[*] GitHub dorks saved to $RESULTS/recon/github/dorks.txt"
echo "[*] Verified secrets found: $(cat $RESULTS/recon/github/trufflehog-org.json | jq 'select(.Verified==true)' | wc -l)"
```

---

## Step 12: Cloud Asset Discovery

Target orgs often have S3 buckets, GCS buckets, and Azure blobs with predictable naming patterns based on company name:

```bash
TARGET="target.com"
ORG="target"   # company name shorthand
RESULTS=~/pentest-toolkit/results/$TARGET
mkdir -p $RESULTS/recon/cloud

# cloud_enum - S3, GCS, Azure all at once with permutation
# https://github.com/initstring/cloud_enum
python3 ~/tools/cloud_enum/cloud_enum.py \
  -k $ORG \
  -k "$ORG-prod" \
  -k "$ORG-dev" \
  -k "$ORG-staging" \
  -k "$ORG-backup" \
  -k "$ORG-data" \
  -k "$ORG-assets" \
  --disable-azure \
  2>/dev/null | tee $RESULTS/recon/cloud/cloud-enum.txt

# S3Scanner - verify access on found buckets
s3scanner scan --buckets-file $RESULTS/recon/cloud/cloud-enum.txt \
  --threads 20 \
  --output $RESULTS/recon/cloud/s3-results.txt 2>/dev/null

# GrayHatWarfare search (web UI - finds exposed buckets via search)
echo "Manual search: https://buckets.grayhatwarfare.com/buckets?keywords=$ORG"

# Check for exposed Firebase databases
curl -sk "https://$ORG.firebaseio.com/.json?shallow=true" -w "%{http_code}" \
  | tee $RESULTS/recon/cloud/firebase-check.txt

# Azure blob storage check
curl -sk "https://$ORG.blob.core.windows.net/?comp=list" -w "%{http_code}" \
  | tee $RESULTS/recon/cloud/azure-check.txt

# Check for exposed Elasticsearch / Kibana (port 9200/5601)
grep -E "9200|5601" $RESULTS/recon/nmap.txt | \
  awk '{print $1}' | while read IP; do
    curl -sk "http://$IP:9200/_cat/indices?v" -o /tmp/es_check.txt
    [[ $(wc -c < /tmp/es_check.txt) -gt 100 ]] && echo "[!] Exposed Elasticsearch: $IP" | tee -a $RESULTS/recon/cloud/exposed-services.txt
  done

echo "[*] Cloud assets found: $(wc -l < $RESULTS/recon/cloud/cloud-enum.txt)"
```

---

## Step 13: Subdomain Takeover Detection

CNAME pointing to a deregistered third-party service = free subdomain takeover. High impact, often Critical/High in bug bounty:

```bash
TARGET="target.com"
RESULTS=~/pentest-toolkit/results/$TARGET

# nuclei takeover templates - fingerprints 72+ services
nuclei -l $RESULTS/recon/all-subdomains.txt \
  -t ~/nuclei-templates/takeovers/ \
  -json -o $RESULTS/recon/takeovers-nuclei.json \
  -silent -severity medium,high,critical

# subjack - checks CNAME chains for dangling pointers
subjack -w $RESULTS/recon/all-subdomains.txt \
  -t 100 -timeout 30 \
  -c ~/tools/subjack/fingerprints.json \
  -o $RESULTS/recon/takeovers-subjack.txt \
  -ssl 2>/dev/null

# Check the potential-takeovers file from DNS step
if [ -s $RESULTS/recon/potential-takeovers.txt ]; then
  echo "[!] Potential takeovers from CNAME analysis:"
  cat $RESULTS/recon/potential-takeovers.txt

  # Verify manually: does the CNAME target return a takeover fingerprint?
  cat $RESULTS/recon/potential-takeovers.txt | awk '{print $1}' | while read SUB; do
    RESPONSE=$(curl -sk "https://$SUB" 2>/dev/null | head -c 500)
    echo "$RESPONSE" | grep -i \
      "there is no app here\|repository not found\|no such app\|does not exist\|bucket does not exist\|page not found\|unclaimed" \
      && echo "[TAKEOVER] $SUB" | tee -a $RESULTS/recon/confirmed-takeovers.txt
  done
fi

echo "[*] Potential takeovers: $(wc -l < $RESULTS/recon/takeovers-subjack.txt 2>/dev/null)"
```

---

## Step 14: Google Dorking + OSINT

Google indexes things the target didn't intend to expose - config files, admin panels, error pages, exposed credentials:

```bash
TARGET="target.com"
RESULTS=~/pentest-toolkit/results/$TARGET

# Save dork list for manual execution
cat << 'EOF' > $RESULTS/recon/google-dorks.txt
# Sensitive files
site:target.com filetype:env OR filetype:yaml OR filetype:json OR filetype:xml OR filetype:config
site:target.com filetype:log OR filetype:sql OR filetype:bak OR filetype:backup OR filetype:old
site:target.com filetype:pdf OR filetype:xlsx OR filetype:docx intext:confidential

# Admin panels / login pages
site:target.com inurl:admin OR inurl:login OR inurl:dashboard OR inurl:panel OR inurl:manage
site:target.com inurl:wp-admin OR inurl:phpmyadmin OR inurl:adminer

# API / Swagger / GraphQL
site:target.com inurl:swagger OR inurl:api-docs OR inurl:graphql OR inurl:openapi

# Error pages / stack traces
site:target.com "error" OR "exception" OR "stack trace" OR "debug"

# Exposed credentials
site:target.com "api_key" OR "apikey" OR "secret" OR "password" OR "token"

# Pastebin / GitHub leaks
site:pastebin.com "target.com"
site:github.com "target.com" password OR secret OR api_key

# Cached sensitive pages
cache:target.com/admin
EOF

# Run automated dork scanning with Google
# Use googler or dorkscout if available
googler --np -n 20 "site:$TARGET filetype:env OR filetype:yaml secret" 2>/dev/null | \
  tee $RESULTS/recon/google-results.txt

# urlscan.io - find indexed screenshots of target pages
curl -s "https://urlscan.io/api/v1/search/?q=domain:$TARGET&size=100" 2>/dev/null | \
  jq -r '.results[].task.url' | sort -u > $RESULTS/recon/urlscan-urls.txt

echo "[*] Google dorks saved. Run manually at: https://google.com"
echo "[*] urlscan.io URLs: $(wc -l < $RESULTS/recon/urlscan-urls.txt)"
```

---

## Step 15: Technology Fingerprinting + Shodan/Censys Intel

```bash
TARGET="target.com"
RESULTS=~/pentest-toolkit/results/$TARGET

# whatweb - framework/CMS fingerprinting
whatweb -i $RESULTS/recon/live-hosts.txt \
  -a 3 --log-json $RESULTS/recon/whatweb.json 2>/dev/null

# Shodan queries for the target
shodan search "hostname:$TARGET" --fields ip_str,port,org,product --limit 200 2>/dev/null | \
  tee $RESULTS/recon/shodan-hostname.txt

# Shodan by IP ranges
cat $RESULTS/recon/ip-ranges.txt | while read CIDR; do
  shodan search "net:$CIDR" --fields ip_str,port,org,product --limit 100 2>/dev/null
done | tee $RESULTS/recon/shodan-asn.txt

# Censys search
censys search "parsed.names: $TARGET" --fields ip,protocols,location.country 2>/dev/null | \
  tee $RESULTS/recon/censys.txt

# nuclei tech detection
nuclei -l $RESULTS/recon/live-hosts.txt \
  -t ~/nuclei-templates/technologies/ \
  -json -o $RESULTS/recon/nuclei-tech.json \
  -silent

# Aggregate tech stack
cat $RESULTS/recon/httpx-full.json | \
  jq -r '.tech[]?' 2>/dev/null | sort | uniq -c | sort -rn | head -30 \
  > $RESULTS/recon/tech-stack.txt
```

---

## Step 16: DNS Advanced Techniques

### 16a: Zone Transfer (AXFR) - Instant Full Zone Dump

Many forgotten/secondary nameservers still allow zone transfers. One successful AXFR gives you every record in the zone instantly:

```bash
TARGET="target.com"
RESULTS=~/pentest-toolkit/results/$TARGET

# Get all nameservers for target
NS_LIST=$(dig NS $TARGET +short | sed 's/\.$//')
echo "Nameservers: $NS_LIST"

# Try AXFR against every nameserver (forgotten ones often still allow it)
for NS in $NS_LIST; do
  echo "[*] Trying AXFR on $NS"
  dig AXFR $TARGET @$NS 2>/dev/null | tee $RESULTS/recon/axfr-$NS.txt
  [[ $(wc -l < $RESULTS/recon/axfr-$NS.txt) -gt 5 ]] && \
    echo "[!] ZONE TRANSFER SUCCESS on $NS" | tee -a $RESULTS/recon/axfr-success.txt
done

# dnsrecon - also tries AXFR + zone walk + brute
dnsrecon -d $TARGET -t axfr 2>/dev/null | tee $RESULTS/recon/dnsrecon-axfr.txt
```

### 16b: DNSSEC NSEC Zone Walking - Enumerate Every Hostname

**Source:** Pen Test Partners research. DNSSEC NSEC records form a sorted linked list of all valid hostnames in the zone. Walking this chain reveals EVERY subdomain without brute-forcing:

```bash
TARGET="target.com"
RESULTS=~/pentest-toolkit/results/$TARGET

# Check if target uses DNSSEC NSEC (not NSEC3)
dig DNSKEY $TARGET +short | head -3
dig $TARGET NSEC | grep -i "NSEC"

# ldns-walk - walks NSEC chain to enumerate all records
ldns-walk @$(dig NS $TARGET +short | head -1 | sed 's/.$//') $TARGET 2>/dev/null | \
  tee $RESULTS/recon/nsec-walk.txt

# dnsrecon zone walk
dnsrecon -d $TARGET -t zonewalk 2>/dev/null | tee $RESULTS/recon/nsec-dnsrecon.txt

# nsec3map - cracks NSEC3 hashes (works even when NSEC3 is used instead of NSEC)
# NSEC3 hashes the names but they can be rainbow-tabled
# https://github.com/anonion0/nsec3map
n3map -f $RESULTS/recon/nsec3-hashes.txt $TARGET 2>/dev/null

# Parse results into subdomain list
grep -oP '[\w-]+\.'$TARGET $RESULTS/recon/nsec-walk.txt | \
  sort -u >> $RESULTS/recon/all-subdomains.txt
sort -u $RESULTS/recon/all-subdomains.txt -o $RESULTS/recon/all-subdomains.txt

echo "[*] NSEC walk found: $(wc -l < $RESULTS/recon/nsec-walk.txt) records"
```

**Why this works:** NSEC was designed to prove non-existence of DNS records for DNSSEC validation. It inadvertently creates a traversable linked list of ALL valid hostnames. One walk = complete zone enumeration without any brute-forcing.

---

## Step 17: Passive DNS Historical Intelligence

Historical DNS records reveal subdomains that existed in the past but were decommissioned - they often still have live backends and fewer security controls:

```bash
TARGET="target.com"
RESULTS=~/pentest-toolkit/results/$TARGET
mkdir -p $RESULTS/recon/passive-dns

# SecurityTrails API - world's largest passive DNS database
curl -s "https://api.securitytrails.com/v1/domain/$TARGET/subdomains?children_only=false&include_inactive=true" \
  -H "apikey: $SECURITYTRAILS_KEY" 2>/dev/null | \
  jq -r '.subdomains[]' | sed "s/$/$TARGET/" | \
  sort -u > $RESULTS/recon/passive-dns/securitytrails.txt

# SecurityTrails historical DNS - find IP changes (pivoting to other assets)
curl -s "https://api.securitytrails.com/v1/history/$TARGET/dns/a" \
  -H "apikey: $SECURITYTRAILS_KEY" 2>/dev/null | \
  jq -r '.records[].values[].ip' | sort -u > $RESULTS/recon/passive-dns/historical-ips.txt

# VirusTotal passive DNS + graph pivoting
# Domain -> IPs it has pointed to -> other domains on those IPs -> more subdomains
VT_KEY=$VIRUSTOTAL_KEY
curl -s "https://www.virustotal.com/api/v3/domains/$TARGET/resolutions?limit=40" \
  -H "x-apikey: $VT_KEY" 2>/dev/null | \
  jq -r '.data[].attributes | "\(.ip_address) | \(.date)"' \
  > $RESULTS/recon/passive-dns/vt-resolutions.txt

# VirusTotal subdomains
curl -s "https://www.virustotal.com/api/v3/domains/$TARGET/subdomains?limit=40" \
  -H "x-apikey: $VT_KEY" 2>/dev/null | \
  jq -r '.data[].id' | sort -u >> $RESULTS/recon/passive-dns/vt-subdomains.txt

# Pivot: for each historical IP, find OTHER domains that pointed to it
cat $RESULTS/recon/passive-dns/historical-ips.txt | while read IP; do
  curl -s "https://www.virustotal.com/api/v3/ip_addresses/$IP/resolutions?limit=40" \
    -H "x-apikey: $VT_KEY" 2>/dev/null | \
    jq -r '.data[].attributes.host_name' 2>/dev/null | \
    grep "$TARGET" | sort -u
done | tee $RESULTS/recon/passive-dns/vt-ip-pivot.txt

# Farsight DNSDB (world's largest passive DNS - 100B+ records)
# Forward lookup: all records for domain
curl -s "https://api.dnsdb.info/dnsdb/v2/lookup/rrset/name/*.$TARGET?limit=1000" \
  -H "X-API-Key: $DNSDB_KEY" 2>/dev/null | \
  jq -r '.obj.rrname' | sort -u | sed 's/\.$//' \
  > $RESULTS/recon/passive-dns/dnsdb-forward.txt

# Merge historical sources
cat $RESULTS/recon/passive-dns/*.txt | \
  grep -E "^[a-zA-Z0-9.-]+\.$TARGET$" | \
  sort -u >> $RESULTS/recon/all-subdomains.txt
sort -u $RESULTS/recon/all-subdomains.txt -o $RESULTS/recon/all-subdomains.txt

echo "[*] Historical subdomains added: $(wc -l < $RESULTS/recon/passive-dns/securitytrails.txt)"
```

---

## Step 18: Advanced Internet Scanner Queries

Beyond basic `hostname:` searches - use full-text search, TLS cert mining, and cross-engine queries for maximum coverage:

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
shodan search "hostname:$TARGET port:8443" --fields ip_str,port,product > /dev/null 2>&1

# --- FOFA (Chinese scanner, massive - 10B+ assets, indexes HTML content) ---
# FOFA has unique full-text search on page content
echo "FOFA queries to run at fofa.info:"
cat << EOF >> $RESULTS/recon/scanners/fofa-queries.txt
domain="$TARGET"
cert="$TARGET"
body="$TARGET" && country="US"
icon_hash="FAVICON_HASH_FROM_STEP7"
header="X-Powered-By: TARGET_TECH"
org="$ORG"
EOF

# --- CENSYS ---
# Full 65k port scan data, all certificates
censys search "parsed.names: $TARGET" \
  --fields ip,protocols,parsed.subject_dn,location.country \
  --pages 10 2>/dev/null > $RESULTS/recon/scanners/censys-certs.txt

# Find all IPs with cert containing target domain
censys search "parsed.names: $TARGET OR parsed.subject.common_name: $TARGET" \
  --fields ip,protocols 2>/dev/null | \
  awk '{print $1}' | sort -u >> $RESULTS/recon/resolved-ips.txt

# --- NETLAS (indexes domains + IPs, emphasis on DNS) ---
echo "Netlas queries at netlas.io:"
cat << EOF >> $RESULTS/recon/scanners/netlas-queries.txt
domain:$TARGET
host:$TARGET
certificate.subject.common_name:$TARGET
whois.org:"$ORG"
EOF

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
echo "ZoomEye queries at zoomeye.org:"
echo "hostname:$TARGET" >> $RESULTS/recon/scanners/zoomeye-queries.txt
echo "site:$TARGET" >> $RESULTS/recon/scanners/zoomeye-queries.txt
```

---

## Step 19: JARM / JA4+ TLS Fingerprinting

**Source:** Salesforce JARM research + FoxIO JA4+ (2024). TLS stack produces a unique fingerprint even when IP/domain changes. Track hidden infrastructure and correlate related assets:

```bash
TARGET="target.com"
RESULTS=~/pentest-toolkit/results/$TARGET
mkdir -p $RESULTS/recon/tls

# JARM fingerprint all live HTTPS hosts
# Same fingerprint across different IPs = same server/config = related infrastructure
cat $RESULTS/recon/live-hosts.txt | grep "https" | awk '{print $3}' | \
  sed 's|https://||' | while read HOST; do
    JARM=$(python3 ~/tools/jarm/jarm.py $HOST 2>/dev/null | grep "JARM:" | awk '{print $2}')
    [[ -n "$JARM" ]] && echo "$JARM | $HOST"
  done | sort > $RESULTS/recon/tls/jarm-fingerprints.txt

# JA4+ fingerprinting (more resilient than JARM, handles ECH/TLS randomization)
# https://github.com/FoxIO-LLC/ja4
cat $RESULTS/recon/resolved-ips.txt | while read IP; do
  ja4 --target $IP:443 2>/dev/null | jq -r '"\(.ja4s) | '"$IP"'"'
done | sort > $RESULTS/recon/tls/ja4-fingerprints.txt

# Group by fingerprint - IPs with same JARM = same server software = related org assets
sort $RESULTS/recon/tls/jarm-fingerprints.txt | \
  awk '{print $1}' | sort | uniq -c | sort -rn | head -20

# Search Shodan for matching JARM fingerprint
MAIN_JARM=$(head -1 $RESULTS/recon/tls/jarm-fingerprints.txt | awk '{print $1}')
[[ -n "$MAIN_JARM" ]] && \
  shodan search "ssl.jarm:$MAIN_JARM" --fields ip_str,port,org --limit 100 \
  > $RESULTS/recon/tls/shodan-jarm-match.txt && \
  echo "[*] Related IPs via JARM: $(wc -l < $RESULTS/recon/tls/shodan-jarm-match.txt)"
```

**Why this matters:** A target may have 50 IPs behind a CDN. All 50 will share the same JARM fingerprint. Finding that fingerprint in Shodan reveals all 50 origins - bypassing CDN protection for every one of them.

---

## Step 20: Supply Chain Recon - Dependency Confusion + Package Discovery

**Source:** Alex Birsan's landmark research (hacked Apple, Microsoft, 35+ companies). Internal package names leaked from JS source maps and package.json in archives can be registered on npm/pypi to achieve RCE on developer machines and CI/CD.

```bash
TARGET="target.com"
ORG="targetorg"
RESULTS=~/pentest-toolkit/results/$TARGET
mkdir -p $RESULTS/recon/supply-chain

# Step 1: Extract package.json files from Wayback / JS archives
# These often contain internal package names that aren't on npm
curl -s "https://web.archive.org/cdx/search/cdx?url=$TARGET/*package.json&output=json&fl=timestamp,original&limit=20" 2>/dev/null | \
  jq -r '.[] | "https://web.archive.org/web/\(.[0])/\(.[1])"' | while read URL; do
    curl -sk "$URL" 2>/dev/null | jq -r '.dependencies | keys[]' 2>/dev/null
    curl -sk "$URL" 2>/dev/null | jq -r '.devDependencies | keys[]' 2>/dev/null
  done | sort -u > $RESULTS/recon/supply-chain/package-names.txt

# Step 2: Mine source maps for internal package names
# Source maps expose original un-minified source, including internal imports
cat $RESULTS/recon/js/js-urls.txt | sed 's/$/.map/' | while read MAP_URL; do
  curl -sk "$MAP_URL" 2>/dev/null | \
    jq -r '.sources[]?' 2>/dev/null | \
    grep -oP "node_modules/([^/]+)" | sort -u
done | sort -u >> $RESULTS/recon/supply-chain/package-names.txt

# Step 3: Check which packages DON'T exist on npm (potential confusion targets)
sort -u $RESULTS/recon/supply-chain/package-names.txt | while read PKG; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://registry.npmjs.org/$PKG")
  if [[ "$STATUS" == "404" ]]; then
    echo "[UNCLAIMED] $PKG" | tee -a $RESULTS/recon/supply-chain/unclaimed-packages.txt
  fi
done

# Step 4: Check PyPI packages (same technique for Python orgs)
grep -i "python\|requirements\|pip" $RESULTS/recon/urls/all-urls.txt | while read URL; do
  curl -sk "$URL" 2>/dev/null | grep -oP "([a-zA-Z0-9_-]+)==[0-9]+" | \
    awk -F= '{print $1}'
done | sort -u | while read PKG; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://pypi.org/pypi/$PKG/json")
  [[ "$STATUS" == "404" ]] && echo "[UNCLAIMED PyPI] $PKG" | tee -a $RESULTS/recon/supply-chain/unclaimed-packages.txt
done

echo "[!] Unclaimed packages (dependency confusion candidates):"
cat $RESULTS/recon/supply-chain/unclaimed-packages.txt
```

---

## Step 21: Wayback CDX API Advanced Mining

The Wayback Machine CDX API is more powerful than most hunters use. Advanced parameters reveal deleted endpoints, old configs, and historical snapshots filtered by exact criteria:

```bash
TARGET="target.com"
RESULTS=~/pentest-toolkit/results/$TARGET
mkdir -p $RESULTS/recon/wayback

CDX="https://web.archive.org/cdx/search/cdx"

# All unique URLs ever indexed for target (collapse=urlkey = deduplicated)
curl -s "$CDX?url=*.$TARGET/*&output=json&fl=original&collapse=urlkey&limit=50000" 2>/dev/null | \
  jq -r '.[][]' | sort -u > $RESULTS/recon/wayback/all-historical-urls.txt

# Only URLs that returned 200 (actually existed, not 404/redirect)
curl -s "$CDX?url=*.$TARGET/*&output=json&fl=original,statuscode&filter=statuscode:200&collapse=urlkey&limit=20000" 2>/dev/null | \
  jq -r '.[] | "\(.[1]) \(.[0])"' | sort -u > $RESULTS/recon/wayback/200-urls.txt

# Find endpoints that were 200 in past but now return 403/404 (shadow endpoints)
curl -s "$CDX?url=*.$TARGET/api/*&output=json&fl=original,statuscode&filter=statuscode:200&from=2020&to=2023&collapse=urlkey" 2>/dev/null | \
  jq -r '.[].[]' | grep "http" | sort -u > $RESULTS/recon/wayback/old-api-endpoints.txt

# Find all parameter names (discover hidden params via historical URLs)
cat $RESULTS/recon/wayback/all-historical-urls.txt | \
  grep "?" | sed 's/=.*/=/' | \
  grep -oP "[\?&][a-zA-Z0-9_]+=" | \
  sed 's/[?&=]//g' | sort | uniq -c | sort -rn | head -50 \
  > $RESULTS/recon/wayback/parameter-names.txt

# Find JS files with snapshots (to mine old versions for secrets/endpoints)
curl -s "$CDX?url=*.$TARGET/*.js&output=json&fl=timestamp,original&filter=statuscode:200&limit=500" 2>/dev/null | \
  jq -r '.[] | "https://web.archive.org/web/\(.[0])/\(.[1])"' \
  >> $RESULTS/recon/js/wayback-js-urls.txt

# Find config/backup files ever exposed
for EXT in env yaml yml json config xml sql bak backup old zip tar gz; do
  curl -s "$CDX?url=*.$TARGET/*.$EXT&output=json&fl=original,statuscode&filter=statuscode:200&collapse=urlkey" 2>/dev/null | \
    jq -r '.[].[]' | grep "http" | tee -a $RESULTS/recon/wayback/exposed-configs.txt
done

echo "[*] Historical URLs: $(wc -l < $RESULTS/recon/wayback/all-historical-urls.txt)"
echo "[*] Old API endpoints (200 in past): $(wc -l < $RESULTS/recon/wayback/old-api-endpoints.txt)"
echo "[*] Exposed configs found: $(wc -l < $RESULTS/recon/wayback/exposed-configs.txt)"
```

---

## Step 22: reconFTW - Orchestration Framework

When you want everything automated in one pipeline, reconFTW orchestrates 50+ tools with dependency management, deduplication, and prioritized output:

```bash
TARGET="target.com"
RESULTS=~/pentest-toolkit/results/$TARGET

# reconFTW full mode - runs everything: passive, active, JS, vulns, screenshots
# https://github.com/six2dez/reconftw
reconftw.sh -d $TARGET -a \
  --output $RESULTS/recon/reconftw/ \
  2>/dev/null

# reconFTW specific modes if full is too slow:
# Subdomain-only
reconftw.sh -d $TARGET -s --output $RESULTS/recon/reconftw/

# Web only (assumes subdomains already known)
reconftw.sh -d $TARGET -w --output $RESULTS/recon/reconftw/

# Passive only (no active requests to target)
reconftw.sh -d $TARGET -p --output $RESULTS/recon/reconftw/

# reconFTW includes:
# - Subdomain enum: subfinder, amass, github-subdomains, crt.sh, chaos
# - Resolution: shuffledns, massdns
# - Live probe: httpx with screenshots
# - URL discovery: gau, waybackurls, katana
# - JS analysis: subjs, mantra, linkfinder
# - Vuln scan: nuclei (all templates), dalfox (XSS), sqlmap
# - Source map extraction: sourcemapper
# - Takeover: nuclei takeover templates
# - Secrets: gitleaks, trufflehog
# - Distributed mode: sends tasks to remote workers (AX Framework)
echo "[*] reconFTW complete - check $RESULTS/recon/reconftw/"
```

---

## Step 23: Write interesting_recon.md

```bash
TARGET="target.com"
RESULTS=~/pentest-toolkit/results/$TARGET

SUBDOMAINS=$(wc -l < $RESULTS/recon/all-subdomains.txt 2>/dev/null || echo 0)
LIVE=$(wc -l < $RESULTS/recon/live-hosts.txt 2>/dev/null || echo 0)
URLS=$(wc -l < $RESULTS/recon/urls/all-urls.txt 2>/dev/null || echo 0)
INTERESTING=$(wc -l < $RESULTS/recon/urls/interesting-urls.txt 2>/dev/null || echo 0)
TAKEOVERS=$(wc -l < $RESULTS/recon/confirmed-takeovers.txt 2>/dev/null || echo 0)

cat > $RESULTS/interesting_recon.md << EOF
## Status
findings-present

## Summary
Target: $TARGET | Subdomains: $SUBDOMAINS | Live hosts: $LIVE | URLs: $URLS | Interesting URLs: $INTERESTING | Confirmed takeovers: $TAKEOVERS

## Critical Findings (Act on These First)
$(cat $RESULTS/recon/confirmed-takeovers.txt 2>/dev/null | head -5 | sed 's/^/- [TAKEOVER] /')
$(cat $RESULTS/recon/github/trufflehog-org.json 2>/dev/null | jq -r '"- [GITHUB SECRET] \(.DetectorName): \(.Raw[:50])"' 2>/dev/null | head -5)
$(cat $RESULTS/recon/cloud/s3-results.txt 2>/dev/null | grep -i "read\|write\|public" | head -5 | sed 's/^/- [CLOUD BUCKET] /')
$(cat $RESULTS/recon/interesting-ports.txt 2>/dev/null | head -5 | sed 's/^/- [EXPOSED SERVICE] /')

## Live Hosts
$(cat $RESULTS/recon/live-hosts.txt 2>/dev/null | head -20)

## Interesting URLs / Endpoints
$(cat $RESULTS/recon/urls/interesting-urls.txt 2>/dev/null | head -20)

## Technology Stack
$(cat $RESULTS/recon/tech-stack.txt 2>/dev/null | head -10)

## Raw Evidence
- Subdomains: $RESULTS/recon/all-subdomains.txt
- Live hosts: $RESULTS/recon/live-hosts.txt
- Port scan: $RESULTS/recon/nmap.txt
- All URLs: $RESULTS/recon/urls/all-urls.txt
- JS analysis: $RESULTS/recon/js/
- GitHub: $RESULTS/recon/github/
- Cloud: $RESULTS/recon/cloud/
- Takeovers: $RESULTS/recon/takeovers-nuclei.json
EOF

cat $RESULTS/interesting_recon.md
```

---

## Phase-End Protocol

Run this before finishing recon. Do not skip.

**1. Write intel back to session.json:**
```bash
SESSION=~/pentest-toolkit/results/<target>/session.json
RESULTS=~/pentest-toolkit/results/<target>

# Live hosts
LIVE_HOSTS=$(cat $RESULTS/recon/live-hosts.txt 2>/dev/null | awk '{print $3}' | head -50 | jq -R . | jq -s .)
# Technologies
TECH=$(cat $RESULTS/recon/tech-stack.txt 2>/dev/null | awk '{print $2}' | sort -u | jq -R . | jq -s .)
# Subdomains count
SUBS=$(cat $RESULTS/recon/all-subdomains.txt 2>/dev/null | wc -l | tr -d ' ')

# Merge into session.json (use jq to update without overwriting other fields)
jq --argjson hosts "$LIVE_HOSTS" \
   --argjson tech "$TECH" \
   '.intel.live_hosts = $hosts | .intel.technologies = $tech' \
   $SESSION > /tmp/session_tmp.json && mv /tmp/session_tmp.json $SESSION
```

**2. Calibrate hypotheses based on what was found:**
```bash
# AWS/cloud tech found → boost cloud-audit hypothesis
grep -qi "aws\|s3\|lambda\|gcp\|azure" $RESULTS/recon/tech-stack.txt 2>/dev/null && \
  echo "[SIGNAL] TECH_DETECTED: cloud provider found → boost cloud-audit hypothesis +15%, flag cloud-audit module"

# WAF detected → activate 403-bypass
cat $RESULTS/recon/httpx-full.json 2>/dev/null | jq -r '.tech[]?' | \
  grep -qi "cloudflare\|akamai\|fastly\|imperva\|f5\|barracuda" && \
  echo "[SIGNAL] WAF_CONFIRMED → activate 403-bypass module"

# JWT in responses → boost JWT confusion hypothesis
grep -qi "jwt\|bearer\|authorization" $RESULTS/recon/httpx-full.json 2>/dev/null && \
  echo "[SIGNAL] JWT_FOUND → boost JWT/OAuth hypotheses +10%"
```

**3. Check fork opportunities (if budget allows and state == WIDE):**
```bash
# Internal services on unusual ports?
grep -E "3306|5432|6379|27017|9200|2375|11211" $RESULTS/recon/interesting-ports.txt 2>/dev/null && \
  echo "[FORK CANDIDATE] Internal service exposed - consider /exploit on specific port"

# Unclaimed packages?
[ -s $RESULTS/recon/supply-chain/unclaimed-packages.txt ] && \
  echo "[FORK CANDIDATE] Unclaimed packages - consider dependency confusion fork"

# AXFR success?
[ -s $RESULTS/recon/axfr-success.txt ] && \
  echo "[FORK CANDIDATE] Zone transfer succeeded - new subdomains, rerun /recon on discovered hosts"
```

**4. Update session.json thread status:**
```bash
jq '.threads[0].phase = "secrets" | .ptt.graph[0].status = "done"' \
  $SESSION > /tmp/s.json && mv /tmp/s.json $SESSION
```

**5. Verify interesting_recon.md was written** (Step 23 does this - confirm file exists before finishing).

Then run `/secrets <target>`.

---

## Quick Reference: Tool Priority by Finding Type

| Goal | Primary Tool | Backup |
|------|-------------|--------|
| Subdomain passive | `subfinder -all` | amass passive, chaos |
| CT logs deep | crt.sh PostgreSQL API | certspotter |
| Subdomain brute | `puredns` + seclists | shuffledns |
| Permutation | `dnsgen` + `gotator` | altdns |
| DNS resolution | `puredns resolve` | massdns |
| Live host probe | `httpx -tech-detect` | httpx basic |
| Port discovery | `naabu -p -` | masscan on ASN CIDRs |
| Port service ID | `nmap -sV -sC` | - |
| URL history | `gau` + `waymore` | waybackurls |
| Wayback CDX advanced | CDX API collapse=urlkey + statuscode filter | waymore |
| Live crawl | `katana -jc` | gospider |
| JS endpoints | `LinkFinder` | `katana` field extract |
| JS secrets | `TruffleHog` verified | SecretFinder |
| GitHub secrets | `trufflehog github --only-verified` | gitleaks |
| Cloud buckets | `cloud_enum` | s3scanner |
| Subdomain takeover | `nuclei -t takeovers/` | subjack |
| Tech stack | `httpx -tech-detect` | whatweb |
| Favicon recon | `httpx -favicon` + shodan | favfreak |
| Shodan/Censys | SSL cert mining + org name + ASN | FOFA, Netlas, ZoomEye |
| FOFA / Netlas | full-text HTML + cert search | Criminal IP, LeakIX |
| Zone transfer (AXFR) | `dig AXFR @ns` all nameservers | dnsrecon -t axfr |
| NSEC zone walk | `ldns-walk` (NSEC) / nsec3map (NSEC3) | dnsrecon -t zonewalk |
| Passive DNS historical | SecurityTrails API + Farsight DNSDB | VirusTotal graph pivot |
| TLS fingerprint | `jarm.py` + Shodan ssl.jarm | JA4+ (FoxIO) |
| Supply chain recon | package.json from Wayback + source map mine | npm/PyPI 404 check |
| Orchestration (all-in-one) | `reconftw.sh -d $TARGET -a` | manual phased steps |

---

## Key Research References

**Core Tools**
- [Chaos ProjectDiscovery - Pre-indexed bug bounty data](https://chaos.projectdiscovery.io)
- [puredns - Wildcard-aware DNS brute-force](https://github.com/d3mondev/puredns)
- [dnsgen - Subdomain permutation](https://github.com/ProjectAnte/dnsgen)
- [katana - JS-aware crawler (ProjectDiscovery)](https://github.com/projectdiscovery/katana)
- [TruffleHog - 800+ verified secret detectors](https://github.com/trufflesecurity/trufflehog)
- [cloud_enum - Multi-cloud asset discovery](https://github.com/initstring/cloud_enum)
- [can-i-take-over-xyz - Takeover fingerprints](https://github.com/EdOverflow/can-i-take-over-xyz)
- [asnmap - Organization IP range mapping](https://github.com/projectdiscovery/asnmap)
- [reconFTW - 50+ tool orchestration framework](https://github.com/six2dez/reconftw)

**Favicon / Fingerprinting**
- [Weaponizing favicon.ico for bug bounties - Medium](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [JARM TLS fingerprinting - Salesforce Engineering](https://engineering.salesforce.com/easily-identify-malicious-servers-on-the-internet-with-jarm-e095edac525a/)
- [JA4+ TLS fingerprinting spec - FoxIO](https://github.com/FoxIO-LLC/ja4)

**DNSSEC Zone Walking**
- [NSEC zone walking explained - Pen Test Partners](https://www.pentestpartners.com/security-blog/dns-zone-walking/)
- [ldns-walk - NSEC enumeration](https://github.com/bfar/ldns-walk)
- [nsec3map - NSEC3 hash cracker](https://github.com/anonion0/nsec3map)

**Passive DNS + Historical Intel**
- [SecurityTrails API - subdomain + passive DNS](https://securitytrails.com/corp/api)
- [Farsight DNSDB - 100B+ passive DNS records](https://www.domaintools.com/resources/blog/introducing-farsight-dnsdb)
- [VirusTotal Graph - domain/IP pivot](https://www.virustotal.com/graph/)

**Advanced Internet Scanners**
- [FOFA - full-text internet asset search (10B+ records)](https://fofa.info)
- [Netlas.io - domain + DNS focused scanner](https://netlas.io)
- [LeakIX - compromised + vulnerable server index](https://leakix.net)
- [Criminal IP - threat intel + attack surface](https://www.criminalip.io)
- [ZoomEye - Asia-region scanner with unique coverage](https://www.zoomeye.org)

**Supply Chain**
- [Dependency Confusion - Alex Birsan (2021)](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610)
- [Sourcemapper - source map extraction](https://github.com/denandz/sourcemapper)

**Methodology**
- [State of Secrets Sprawl 2025 - GitGuardian](https://blog.gitguardian.com/the-state-of-secrets-sprawl-2025/)
- [Bug Bounty Methodology 2025](https://github.com/amrelsagaei/Bug-Bounty-Hunting-Methodology-2025)
