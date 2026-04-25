# Recon Step 13: Subdomain Takeover Detection

CNAME pointing to a deregistered third-party service = free subdomain takeover. High impact, often Critical/High in bug bounty.

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

## Takeover Fingerprints Reference

| Service | Fingerprint string | Notes |
|---|---|---|
| GitHub Pages | "There isn't a GitHub Pages site here" | Register repo |
| Heroku | "no such app" | Register Heroku app |
| Shopify | "Sorry, this shop is currently unavailable" | Register store |
| Fastly | "Fastly error: unknown domain:" | Claim in Fastly |
| S3 bucket | "NoSuchBucket" | Create bucket with same name |
| Zendesk | "Help Center Closed" | Claim subdomain |
| Ghost | "The thing you were looking for is no longer here" | Register blog |
| Surge.sh | "project not found" | Claim project |
| WordPress.com | "Do you want to register *.wordpress.com?" | Register blog |

## NS Takeover (Higher Impact)

```bash
# If NS records point to nameservers that no longer exist:
for SUB in $(cat $RESULTS/recon/all-subdomains.txt | head -100); do
  NS_RECORDS=$(dig NS $SUB +short 2>/dev/null)
  for NS in $NS_RECORDS; do
    # Check if NS domain itself resolves
    NS_IP=$(dig +short $NS 2>/dev/null)
    [[ -z "$NS_IP" ]] && echo "[!] NS TAKEOVER: $SUB -> NS $NS does not resolve!" | \
      tee -a $RESULTS/recon/ns-takeover.txt
  done
done
```

**Signal:** `emit_signal VULN_CONFIRMED "Subdomain takeover confirmed: <subdomain> -> <service>" "main/recon" 0.95`
