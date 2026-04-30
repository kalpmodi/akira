# Recon Step 12: Cloud Asset Discovery

Target orgs often have S3 buckets, GCS buckets, and Azure blobs with predictable naming patterns based on company name.

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
  2>/dev/null | tee $RESULTS/recon/cloud/cloud-enum.txt

# S3Scanner - verify access on found buckets
s3scanner scan --buckets-file $RESULTS/recon/cloud/cloud-enum.txt \
  --threads 20 \
  --output $RESULTS/recon/cloud/s3-results.txt 2>/dev/null

# GrayHatWarfare search (web UI - finds exposed buckets via search):
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
    [[ $(wc -c < /tmp/es_check.txt) -gt 100 ]] && \
      echo "[!] Exposed Elasticsearch: $IP" | tee -a $RESULTS/recon/cloud/exposed-services.txt
  done

echo "[*] Cloud assets found: $(wc -l < $RESULTS/recon/cloud/cloud-enum.txt)"
```

## Additional Cloud Checks

```bash
# GCP - check for public GCS buckets
for NAME in $ORG "$ORG-prod" "$ORG-dev" "$ORG-backup" "$ORG-assets"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://storage.googleapis.com/$NAME")
  [[ "$STATUS" == "200" || "$STATUS" == "301" ]] && \
    echo "[!] GCS bucket accessible: $NAME" | tee -a $RESULTS/recon/cloud/gcs-public.txt
done

# AWS S3 via subdomain detection (s3.amazonaws.com pattern in CNAME):
grep -i "amazonaws.com" $RESULTS/recon/dns-records.txt | \
  grep "CNAME" | awk '{print $1, $NF}' | tee $RESULTS/recon/cloud/s3-cnames.txt

# Verify each S3 CNAME:
cat $RESULTS/recon/cloud/s3-cnames.txt | awk '{print $2}' | while read BUCKET_URL; do
  BUCKET_NAME=$(echo $BUCKET_URL | sed 's/.s3.amazonaws.com//')
  aws s3 ls s3://$BUCKET_NAME --no-sign-request 2>/dev/null && \
    echo "[!] S3 bucket public: $BUCKET_NAME"
done
```

**Signal:** `emit_signal SURFACE_FOUND "Cloud bucket accessible: <bucket-name> (<read/write>)" "main/recon" 0.93`
