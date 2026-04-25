# Recon Step 23: Write interesting_recon.md + Phase-End Protocol

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

## Phase-End Protocol

### 1. Write intel back to session.json

```bash
SESSION=~/pentest-toolkit/results/<target>/session.json
RESULTS=~/pentest-toolkit/results/<target>

LIVE_HOSTS=$(cat $RESULTS/recon/live-hosts.txt 2>/dev/null | awk '{print $3}' | head -50 | jq -R . | jq -s .)
TECH=$(cat $RESULTS/recon/tech-stack.txt 2>/dev/null | awk '{print $2}' | sort -u | jq -R . | jq -s .)
SUBS=$(cat $RESULTS/recon/all-subdomains.txt 2>/dev/null | wc -l | tr -d ' ')

jq --argjson hosts "$LIVE_HOSTS" \
   --argjson tech "$TECH" \
   '.intel.live_hosts = $hosts | .intel.technologies = $tech' \
   $SESSION > /tmp/session_tmp.json && mv /tmp/session_tmp.json $SESSION
```

### 2. Calibrate hypotheses based on what was found

```bash
grep -qi "aws\|s3\|lambda\|gcp\|azure" $RESULTS/recon/tech-stack.txt 2>/dev/null && \
  echo "[SIGNAL] TECH_DETECTED: cloud provider found -> boost cloud-audit hypothesis +15%"

cat $RESULTS/recon/httpx-full.json 2>/dev/null | jq -r '.tech[]?' | \
  grep -qi "cloudflare\|akamai\|fastly\|imperva\|f5\|barracuda" && \
  echo "[SIGNAL] WAF_CONFIRMED -> activate 403-bypass module"

grep -qi "jwt\|bearer\|authorization" $RESULTS/recon/httpx-full.json 2>/dev/null && \
  echo "[SIGNAL] JWT_FOUND -> boost JWT/OAuth hypotheses +10%"
```

### 3. Check fork opportunities (STATE == WIDE)

```bash
grep -E "3306|5432|6379|27017|9200|2375|11211" $RESULTS/recon/interesting-ports.txt 2>/dev/null && \
  echo "[FORK CANDIDATE] Internal service exposed - consider /exploit on specific port"

[ -s $RESULTS/recon/supply-chain/unclaimed-packages.txt ] && \
  echo "[FORK CANDIDATE] Unclaimed packages - consider dependency confusion fork"

[ -s $RESULTS/recon/axfr-success.txt ] && \
  echo "[FORK CANDIDATE] Zone transfer succeeded - rerun /recon on discovered hosts"
```

### 4. Completion Gate

```bash
PENDING_MUST=$(jq '[.scalpel.active_manifest.items[] | select(.priority=="MUST" and .status=="pending")] | length' $SESSION 2>/dev/null || echo 0)
if [ "$PENDING_MUST" -gt 0 ]; then
  echo "=== COMPLETION GATE BLOCKED ==="
  echo "$PENDING_MUST MUST items not completed:"
  jq '.scalpel.active_manifest.items[] | select(.priority=="MUST" and .status=="pending") | "\(.id): \(.tool) on \(.target)"' $SESSION
  echo "Complete or skip with reason before proceeding to secrets phase."
fi
```

### 5. Write Intel Relay

```bash
JS_BUNDLE_URLS=$(grep -oE "https?://[^ \"']*\.js[^\"' ]*" $RESULTS/interesting_recon.md 2>/dev/null | sort -u | head -50 | jq -R . | jq -s .)
GITHUB_ORGS=$(grep -oE "github\.com/([a-zA-Z0-9_-]+)" $RESULTS/recon/github/dorks.txt 2>/dev/null | awk -F/ '{print $2}' | sort -u | head -5 | jq -R . | jq -s . || echo "[]")
LIVE_HOSTS_WITH_TECH=$(cat $RESULTS/recon/httpx-full.json 2>/dev/null | jq -s '[.[] | {host: .url, tech: (.tech // []), status: .status_code}]' || echo "[]")
INTERESTING_ENDPOINTS=$(cat $RESULTS/recon/urls/interesting-urls.txt 2>/dev/null | head -50 | jq -R . | jq -s . || echo "[]")
PARAM_NAMES=$(cat $RESULTS/recon/wayback/parameter-names.txt 2>/dev/null | awk '{print $2}' | head -30 | jq -R . | jq -s . || echo "[]")
WAYBACK_API=$(cat $RESULTS/recon/wayback/old-api-endpoints.txt 2>/dev/null | head -30 | jq -R . | jq -s . || echo "[]")
OPEN_PORTS=$(cat $RESULTS/recon/interesting-ports.txt 2>/dev/null | grep -oE "[0-9]+$" | sort -u | jq -R . | jq -s . || echo "[]")
AWS_HINT=$(grep -qi "aws\|s3\|lambda\|cloudfront" $RESULTS/recon/tech-stack.txt 2>/dev/null && echo true || echo false)
GCP_HINT=$(grep -qi "gcp\|google cloud\|appspot\|googleapis" $RESULTS/recon/tech-stack.txt 2>/dev/null && echo true || echo false)

jq --argjson js "$JS_BUNDLE_URLS" \
   --argjson orgs "$GITHUB_ORGS" \
   --argjson hosts "$LIVE_HOSTS_WITH_TECH" \
   --argjson endpoints "$INTERESTING_ENDPOINTS" \
   --argjson params "$PARAM_NAMES" \
   --argjson wayback "$WAYBACK_API" \
   --argjson ports "$OPEN_PORTS" \
   --argjson aws "$AWS_HINT" \
   --argjson gcp "$GCP_HINT" \
   '.intel_relay.from_recon = {
     "js_bundle_urls": $js,
     "github_orgs": $orgs,
     "live_hosts_with_tech": $hosts,
     "interesting_endpoints": $endpoints,
     "parameter_names": $params,
     "wayback_api_endpoints": $wayback,
     "open_ports": $ports,
     "cloud_hints": {"aws": $aws, "gcp": $gcp, "azure": false}
   }' \
   $SESSION > /tmp/s.json && mv /tmp/s.json $SESSION

echo "[RELAY] Intel relay written:"
echo "  JS bundles: $(echo $JS_BUNDLE_URLS | jq 'length') URLs"
echo "  GitHub orgs: $(echo $GITHUB_ORGS | jq 'length')"
echo "  Live hosts: $(echo $LIVE_HOSTS_WITH_TECH | jq 'length')"
echo "  Interesting endpoints: $(echo $INTERESTING_ENDPOINTS | jq 'length')"
```
