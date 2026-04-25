# Recon Steps 9-10: URL Discovery + JavaScript Analysis

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
  -jc \
  -d 5 \
  -aff \
  -kf robotstxt,sitemapxml \
  -o $RESULTS/recon/urls/katana.txt \
  -silent

# Merge and filter for interesting paths
cat $RESULTS/recon/urls/gau.txt \
    $RESULTS/recon/urls/waymore.txt \
    $RESULTS/recon/urls/katana.txt \
    2>/dev/null | sort -u > $RESULTS/recon/urls/all-urls.txt

grep -iE "admin|config|backup|\.env|\.git|api/|internal|swagger|graphql|upload|debug|test|dev|staging|\?.*=" \
  $RESULTS/recon/urls/all-urls.txt | sort -u > $RESULTS/recon/urls/interesting-urls.txt

echo "[*] Total URLs: $(wc -l < $RESULTS/recon/urls/all-urls.txt)"
echo "[*] Interesting URLs: $(wc -l < $RESULTS/recon/urls/interesting-urls.txt)"
```

## Step 10: JavaScript Analysis - Endpoint + Secret Extraction

JS files are goldmines - hardcoded API keys, internal endpoints, auth tokens, GraphQL schemas not visible from surface:

```bash
mkdir -p $RESULTS/recon/js $RESULTS/recon/js/files

# Extract all JS file URLs from discovered URLs
grep "\.js$\|\.js?" $RESULTS/recon/urls/all-urls.txt | sort -u > $RESULTS/recon/js/js-urls.txt

# Download all JS files
cat $RESULTS/recon/js/js-urls.txt | while read URL; do
  FILENAME=$(echo $URL | md5sum | cut -d' ' -f1).js
  curl -sk "$URL" -o "$RESULTS/recon/js/files/$FILENAME" 2>/dev/null
  echo "$URL -> $FILENAME" >> $RESULTS/recon/js/url-map.txt
done

# LinkFinder - extract endpoints and paths from JS
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

**Signal:** `emit_signal CRED_FOUND "JS secret: <detector> key found in <file>" "main/recon" 0.92`
