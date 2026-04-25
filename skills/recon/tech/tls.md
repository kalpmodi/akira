# Recon Step 19: JARM / JA4+ TLS Fingerprinting

**Source:** Salesforce JARM research + FoxIO JA4+ (2024). TLS stack produces a unique fingerprint even when IP/domain changes. Track hidden infrastructure and correlate related assets.

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

# Search Shodan for matching JARM fingerprint (bypass CDN - finds all origin IPs)
MAIN_JARM=$(head -1 $RESULTS/recon/tls/jarm-fingerprints.txt | awk '{print $1}')
[[ -n "$MAIN_JARM" ]] && \
  shodan search "ssl.jarm:$MAIN_JARM" --fields ip_str,port,org --limit 100 \
  > $RESULTS/recon/tls/shodan-jarm-match.txt && \
  echo "[*] Related IPs via JARM: $(wc -l < $RESULTS/recon/tls/shodan-jarm-match.txt)"
```

**Why this matters:** A target may have 50 IPs behind a CDN. All 50 will share the same JARM fingerprint. Finding that fingerprint in Shodan reveals all 50 origins - bypassing CDN protection for every one of them.

## httpx JARM Integration

httpx collects JARM during Step 6. Extract and cross-reference:

```bash
# Extract JARM hashes from httpx output (already collected in Step 6)
cat $RESULTS/recon/httpx-full.json | \
  jq -r 'select(.jarm != null) | "\(.jarm) | \(.url)"' \
  >> $RESULTS/recon/tls/jarm-fingerprints.txt

# Find duplicate JARM hashes (same backend, different domain)
sort $RESULTS/recon/tls/jarm-fingerprints.txt | \
  awk '{print $1}' | sort | uniq -c | sort -rn | \
  awk '$1 > 1 {print}' | head -10

# For each repeated JARM, list all associated hosts
sort $RESULTS/recon/tls/jarm-fingerprints.txt | \
  awk '{print $1}' | sort | uniq -d | while read JARM; do
    echo "=== JARM: $JARM ==="
    grep "^$JARM" $RESULTS/recon/tls/jarm-fingerprints.txt | awk '{print $3}'
  done
```

**Signal:** `emit_signal SURFACE_FOUND "JARM fingerprint <hash> matches <N> additional IPs in Shodan" "main/recon" 0.85`
