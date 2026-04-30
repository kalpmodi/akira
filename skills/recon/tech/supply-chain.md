# Recon Step 20: Supply Chain Recon - Dependency Confusion + Package Discovery

**Source:** Alex Birsan's landmark research (hacked Apple, Microsoft, 35+ companies). Internal package names leaked from JS source maps and package.json in archives can be registered on npm/pypi to achieve RCE on developer machines and CI/CD.

```bash
TARGET="target.com"
ORG="targetorg"
RESULTS=~/pentest-toolkit/results/$TARGET
mkdir -p $RESULTS/recon/supply-chain

# Step 1: Extract package.json files from Wayback / JS archives
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
  curl -sk "$URL" 2>/dev/null | grep -oP "([a-zA-Z0-9_-]+)==[0-9]+" | awk -F= '{print $1}'
done | sort -u | while read PKG; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://pypi.org/pypi/$PKG/json")
  [[ "$STATUS" == "404" ]] && echo "[UNCLAIMED PyPI] $PKG" | tee -a $RESULTS/recon/supply-chain/unclaimed-packages.txt
done

echo "[!] Unclaimed packages (dependency confusion candidates):"
cat $RESULTS/recon/supply-chain/unclaimed-packages.txt
```

## Extended Supply Chain Checks

```bash
# requirements.txt from Wayback
curl -s "https://web.archive.org/cdx/search/cdx?url=$TARGET/*requirements.txt&output=json&fl=timestamp,original&filter=statuscode:200&limit=10" 2>/dev/null | \
  jq -r '.[] | "https://web.archive.org/web/\(.[0])/\(.[1])"' | while read URL; do
    curl -sk "$URL" 2>/dev/null | grep -oP "^[a-zA-Z0-9_-]+" 2>/dev/null
  done | sort -u | while read PKG; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://pypi.org/pypi/$PKG/json")
    [[ "$STATUS" == "404" ]] && echo "[UNCLAIMED PyPI from requirements.txt] $PKG"
  done | tee -a $RESULTS/recon/supply-chain/unclaimed-packages.txt

# Go modules - check go.mod files
curl -s "https://web.archive.org/cdx/search/cdx?url=$TARGET/*go.mod&output=json&fl=timestamp,original&filter=statuscode:200&limit=10" 2>/dev/null | \
  jq -r '.[] | "https://web.archive.org/web/\(.[0])/\(.[1])"' | while read URL; do
    curl -sk "$URL" 2>/dev/null | grep "require" | awk '{print $2}'
  done | sort -u >> $RESULTS/recon/supply-chain/go-modules.txt
```

**Signal:** `emit_signal SURFACE_FOUND "Dependency confusion candidate: <pkg> on <registry> unclaimed" "main/recon" 0.90`
