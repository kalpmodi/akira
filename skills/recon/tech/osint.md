# Recon Steps 14-15: Google Dorking + OSINT + Shodan/Censys

## Step 14: Google Dorking + OSINT

Google indexes things the target didn't intend to expose - config files, admin panels, error pages, exposed credentials:

```bash
TARGET="target.com"
RESULTS=~/pentest-toolkit/results/$TARGET

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

# Run automated dork scanning
googler --np -n 20 "site:$TARGET filetype:env OR filetype:yaml secret" 2>/dev/null | \
  tee $RESULTS/recon/google-results.txt

# urlscan.io - find indexed screenshots of target pages
curl -s "https://urlscan.io/api/v1/search/?q=domain:$TARGET&size=100" 2>/dev/null | \
  jq -r '.results[].task.url' | sort -u > $RESULTS/recon/urlscan-urls.txt

echo "[*] Google dorks saved. Run manually at: https://google.com"
echo "[*] urlscan.io URLs: $(wc -l < $RESULTS/recon/urlscan-urls.txt)"
```

## Step 15: Technology Fingerprinting + Shodan/Censys Intel

```bash
TARGET="target.com"
ORG="Target Corp"
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

**Signal:** `emit_signal TECH_DETECTED "<tech> version <ver> confirmed on <N> hosts" "main/recon" 0.85`
