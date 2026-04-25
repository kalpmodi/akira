# Recon Steps 1-5: ASN/IP Mapping + Subdomain Enumeration + DNS Resolution

## Step 1: Setup + ASN/IP Range Mapping

Start wide - map the organization's entire IP space, not just the given domain. Shadow assets often live on IP ranges not connected to the main domain.

```bash
TARGET="target.com"
ORG="Target Corp"   # adjust to org name as it appears in WHOIS/ARIN
RESULTS=~/pentest-toolkit/results/$TARGET
mkdir -p $RESULTS/recon

# asnmap: https://github.com/projectdiscovery/asnmap
echo "$ORG" | asnmap -json 2>/dev/null | tee $RESULTS/recon/asn.json
# Also query bgp.he.net manually: https://bgp.he.net/search?search[search]=$ORG

cat $RESULTS/recon/asn.json | jq -r '.[] | .cidr[]?' 2>/dev/null > $RESULTS/recon/ip-ranges.txt

whois $TARGET | tee $RESULTS/recon/whois.txt
whois -h whois.arin.net "n $ORG" 2>/dev/null | grep -i "CIDR\|NetRange" | tee -a $RESULTS/recon/ip-ranges.txt

echo "[*] IP ranges found: $(wc -l < $RESULTS/recon/ip-ranges.txt)"
```

## Step 2: Passive Subdomain Enumeration (Multi-Source)

Query as many passive sources as possible - each source finds subdomains others miss:

```bash
# Subfinder - queries 40+ passive sources (CT logs, DNS DBs, search engines)
subfinder -d $TARGET -all -recursive -o $RESULTS/recon/subfinder.txt -silent

# Amass passive - CAIDA, ARIN, BGP, DNS, ThreatCrowd, etc.
amass enum -passive -d $TARGET -o $RESULTS/recon/amass.txt -config ~/.config/amass/config.yaml 2>/dev/null

# Assetfinder - Certspotter + Hackertarget + Facebook CT + crt.sh
assetfinder --subs-only $TARGET | tee $RESULTS/recon/assetfinder.txt

# Chaos (ProjectDiscovery) - pre-indexed bug bounty program data
chaos -d $TARGET -silent -key $CHAOS_KEY 2>/dev/null | tee $RESULTS/recon/chaos.txt

cat $RESULTS/recon/subfinder.txt $RESULTS/recon/amass.txt \
    $RESULTS/recon/assetfinder.txt $RESULTS/recon/chaos.txt \
    2>/dev/null | sort -u > $RESULTS/recon/passive-all.txt

echo "[*] Unique passive subdomains: $(wc -l < $RESULTS/recon/passive-all.txt)"
```

## Step 3: Certificate Transparency Deep Mining

CT logs are comprehensive - every certificate ever issued is logged. The PostgreSQL API allows deeper queries than the web UI:

```bash
# crt.sh - wildcard query picks up all subdomains including *.subdomain.target.com
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" 2>/dev/null | \
  jq -r '.[].name_value' | sed 's/\*\.//g' | grep -v "^$" | \
  sort -u > $RESULTS/recon/crt-sh.txt

# crt.sh PostgreSQL API (faster, more results):
psql -h crt.sh -U guest certwatch 2>/dev/null << 'EOF'
SELECT DISTINCT ci.NAME_VALUE
FROM certificate_identity ci
JOIN certificate c ON c.id = ci.certificate_id
JOIN ca ON ca.id = c.issuer_ca_id
WHERE ci.NAME_TYPE = 'dNSName'
  AND ci.NAME_VALUE ILIKE '%target.com'
  AND x509_notAfter(c.certificate) > NOW() - INTERVAL '5 years';
EOF

# Certspotter - different log sources than crt.sh
curl -s "https://api.certspotter.com/v1/issuances?domain=$TARGET&include_subdomains=true&expand=dns_names" \
  -H "Authorization: Bearer $CERTSPOTTER_KEY" 2>/dev/null | \
  jq -r '.[].dns_names[]' | sort -u | tee $RESULTS/recon/certspotter.txt

cat $RESULTS/recon/crt-sh.txt $RESULTS/recon/certspotter.txt | sort -u >> $RESULTS/recon/passive-all.txt
sort -u $RESULTS/recon/passive-all.txt -o $RESULTS/recon/passive-all.txt

echo "[*] After CT mining: $(wc -l < $RESULTS/recon/passive-all.txt) unique subdomains"
```

## Step 4: Active Subdomain Brute-Force + Permutation

Passive sources miss internal names and recently added subdomains:

```bash
# puredns - DNS brute-force with wildcard detection
puredns bruteforce \
  /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  $TARGET \
  --resolvers ~/pentest-toolkit/wordlists/resolvers.txt \
  --write $RESULTS/recon/puredns-brute.txt \
  --write-wildcards $RESULTS/recon/wildcards.txt

# dnsgen - generates permutation variants: api-dev, api-staging, api2, api-v2, etc.
cat $RESULTS/recon/passive-all.txt | dnsgen - | \
  puredns resolve --resolvers ~/pentest-toolkit/wordlists/resolvers.txt \
  --write $RESULTS/recon/dnsgen-resolved.txt

# gotator - more aggressive permutation (prefixes, suffixes, swaps)
gotator -sub $RESULTS/recon/passive-all.txt \
  -perm ~/pentest-toolkit/wordlists/gotator-perms.txt \
  -depth 1 -numbers 3 -md -prefixes -adv 2>/dev/null | \
  puredns resolve --resolvers ~/pentest-toolkit/wordlists/resolvers.txt \
  --write $RESULTS/recon/gotator-resolved.txt

cat $RESULTS/recon/puredns-brute.txt $RESULTS/recon/dnsgen-resolved.txt \
    $RESULTS/recon/gotator-resolved.txt $RESULTS/recon/passive-all.txt \
    2>/dev/null | sort -u > $RESULTS/recon/all-subdomains.txt

echo "[*] Total unique subdomains: $(wc -l < $RESULTS/recon/all-subdomains.txt)"
```

## Step 5: DNS Resolution + Wildcard Detection

Resolve all found subdomains to IPs. Filter wildcards - they false-positive all DNS queries:

```bash
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

**Signal:** `emit_signal SURFACE_FOUND "Subdomain enumeration complete: <N> subdomains, <M> resolved" "main/recon" 0.80`
