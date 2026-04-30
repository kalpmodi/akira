# Recon Steps 16-17: DNS Advanced Techniques + Passive DNS History

## Step 16a: Zone Transfer (AXFR) - Instant Full Zone Dump

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

**Signal:** `emit_signal SURFACE_FOUND "ZONE TRANSFER SUCCESS on <NS> for <target> - full zone dump" "main/recon" 0.97`

## Step 16b: DNSSEC NSEC Zone Walking - Enumerate Every Hostname

NSEC records form a sorted linked list of all valid hostnames in the zone. Walking this chain reveals EVERY subdomain without brute-forcing:

```bash
# Check if target uses DNSSEC NSEC (not NSEC3)
dig DNSKEY $TARGET +short | head -3
dig $TARGET NSEC | grep -i "NSEC"

# ldns-walk - walks NSEC chain to enumerate all records
ldns-walk @$(dig NS $TARGET +short | head -1 | sed 's/.$//') $TARGET 2>/dev/null | \
  tee $RESULTS/recon/nsec-walk.txt

# dnsrecon zone walk
dnsrecon -d $TARGET -t zonewalk 2>/dev/null | tee $RESULTS/recon/nsec-dnsrecon.txt

# nsec3map - cracks NSEC3 hashes (works even when NSEC3 is used instead of NSEC)
# https://github.com/anonion0/nsec3map
n3map -f $RESULTS/recon/nsec3-hashes.txt $TARGET 2>/dev/null

# Parse results into subdomain list
grep -oP '[\w-]+\.'$TARGET $RESULTS/recon/nsec-walk.txt | \
  sort -u >> $RESULTS/recon/all-subdomains.txt
sort -u $RESULTS/recon/all-subdomains.txt -o $RESULTS/recon/all-subdomains.txt

echo "[*] NSEC walk found: $(wc -l < $RESULTS/recon/nsec-walk.txt) records"
```

**Why this works:** NSEC was designed to prove non-existence of DNS records for DNSSEC validation. It inadvertently creates a traversable linked list of ALL valid hostnames - one walk = complete zone enumeration without any brute-forcing.

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
curl -s "https://www.virustotal.com/api/v3/domains/$TARGET/resolutions?limit=40" \
  -H "x-apikey: $VIRUSTOTAL_KEY" 2>/dev/null | \
  jq -r '.data[].attributes | "\(.ip_address) | \(.date)"' \
  > $RESULTS/recon/passive-dns/vt-resolutions.txt

# VirusTotal subdomains
curl -s "https://www.virustotal.com/api/v3/domains/$TARGET/subdomains?limit=40" \
  -H "x-apikey: $VIRUSTOTAL_KEY" 2>/dev/null | \
  jq -r '.data[].id' | sort -u >> $RESULTS/recon/passive-dns/vt-subdomains.txt

# Pivot: for each historical IP, find OTHER domains that pointed to it
cat $RESULTS/recon/passive-dns/historical-ips.txt | while read IP; do
  curl -s "https://www.virustotal.com/api/v3/ip_addresses/$IP/resolutions?limit=40" \
    -H "x-apikey: $VIRUSTOTAL_KEY" 2>/dev/null | \
    jq -r '.data[].attributes.host_name' 2>/dev/null | \
    grep "$TARGET" | sort -u
done | tee $RESULTS/recon/passive-dns/vt-ip-pivot.txt

# Farsight DNSDB (world's largest passive DNS - 100B+ records)
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
