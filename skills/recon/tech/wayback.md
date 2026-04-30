# Recon Step 21: Wayback CDX API Advanced Mining

The Wayback Machine CDX API is more powerful than most hunters use. Advanced parameters reveal deleted endpoints, old configs, and historical snapshots filtered by exact criteria.

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

## Advanced CDX Queries

```bash
# Find all subdomains ever indexed (expand scope)
curl -s "$CDX?url=*.$TARGET&output=json&fl=original&collapse=domain&limit=10000" 2>/dev/null | \
  jq -r '.[][]' | grep -oE "https?://[^/]+" | sort -u | \
  sed 's|https://||;s|http://||' >> $RESULTS/recon/all-subdomains.txt

# Find endpoints with specific extensions in paths (internal tools exposed historically)
for EXT in php asp aspx cfm jsp do cgi; do
  curl -s "$CDX?url=*.$TARGET/*.$EXT&output=json&fl=original&filter=statuscode:200&collapse=urlkey&limit=1000" 2>/dev/null | \
    jq -r '.[][]' | grep "http" | sort -u
done | sort -u > $RESULTS/recon/wayback/legacy-endpoints.txt

# Wayback Sparkline - check crawl frequency (high frequency = important/changing page)
curl -s "https://web.archive.org/__sparkline__?output=json&url=$TARGET" 2>/dev/null | \
  jq -r '.years | to_entries[] | "\(.key): \(.value | add) snapshots"'
```

**Signal:** `emit_signal SURFACE_FOUND "Wayback: <N> historical API endpoints found, <M> exposed configs" "main/recon" 0.80`
