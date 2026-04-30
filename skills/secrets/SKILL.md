---
name: secrets
description: Use when hunting for secrets, API keys, tokens, or credentials on a pentest target, running phase 2 of an engagement, scanning JS files for hardcoded secrets, or running trufflehog/gitleaks. Also use when the user says "run secrets", "hunt secrets", or "phase 2".
---

# Secrets Hunting Phase

## Overview

Hunts credentials across every surface the target has ever touched:
JS bundles, GitHub repos, deleted commits, Postman collections, API specs, .env files, cloud configs.

This phase does NOT run generically. It reads exactly what recon found and targets THOSE
specific assets. TruffleHog runs on the actual JS bundle URLs from recon, not on the domain name.

See `references/intelligence-protocol.md` for the full coordination contract.

---

## Phase 0: Smart Intake (Run Before Any Tool)

```bash
source ~/.claude/skills/_shared/phase0.sh
source ~/.claude/skills/_shared/signals.sh

p0_init_vars "$1"
p0_state_gate "HARVEST" || exit 0
p0_read_relay recon
p0_read_memory
p0_read_hypotheses

echo "=== SECRETS SMART INTAKE: $TARGET ==="
echo "State: $STATE | Top hypothesis: $TOP_HYPO_LABEL [$TOP_HYPO_PROB%]"
echo "JS bundles to scan: $(echo "$JS_BUNDLES" | wc -l | tr -d ' ')"
echo "GitHub orgs found: $(echo "$GITHUB_ORGS" | tr ' ' '\n' | wc -l | tr -d ' ')"
echo "Live hosts: $(echo "$LIVE_HOSTS" | wc -l | tr -d ' ')"
echo "AWS mode: $AWS_HINT | WAF: $WAF"
echo "ATW flagged (will skip): $ATW_FLAGGED"
echo ""
```

---

## Phase 1: Build Execution Manifest

Generate the manifest BEFORE running a single tool. Write it to session.json.
Every MUST item MUST complete before this phase ends.

```bash
# Build manifest items dynamically from smart intake
MANIFEST_ITEMS="[]"

# M01: TruffleHog on discovered JS bundles (MUST if bundles found)
[ -n "$JS_BUNDLES" ] && MANIFEST_ITEMS=$(echo $MANIFEST_ITEMS | jq '. + [{"id":"m01","tool":"trufflehog","target":"js_bundles","reason":"JS bundles found in recon - primary secret surface","priority":"MUST","status":"pending"}]')

# M02: TruffleHog on GitHub org (MUST if org found)
[ -n "$GITHUB_ORGS" ] && MANIFEST_ITEMS=$(echo $MANIFEST_ITEMS | jq '. + [{"id":"m02","tool":"trufflehog_github","target":"github_org","reason":"GitHub org identified in recon","priority":"MUST","status":"pending"}]')

# M03: Gitleaks on downloaded repos (SHOULD)
MANIFEST_ITEMS=$(echo $MANIFEST_ITEMS | jq '. + [{"id":"m03","tool":"gitleaks","target":"github_repos","reason":"Regex-based detection catches patterns TruffleHog misses","priority":"SHOULD","status":"pending"}]')

# M04: Postman collection hunting (MUST - often missed, high value)
MANIFEST_ITEMS=$(echo $MANIFEST_ITEMS | jq '. + [{"id":"m04","tool":"postman_hunt","target":"postman.com","reason":"Postman collections often contain API keys + internal endpoints","priority":"MUST","status":"pending"}]')

# M05: API spec hunting on all live hosts (MUST)
MANIFEST_ITEMS=$(echo $MANIFEST_ITEMS | jq '. + [{"id":"m05","tool":"swagger_hunt","target":"live_hosts","reason":"Exposed API specs reveal all endpoints including auth-required ones","priority":"MUST","status":"pending"}]')

# M06: .env / config file hunting (MUST)
MANIFEST_ITEMS=$(echo $MANIFEST_ITEMS | jq '. + [{"id":"m06","tool":"env_hunt","target":"live_hosts","reason":"Accidentally exposed config files","priority":"MUST","status":"pending"}]')

# M07: AWS-specific hunting (MUST if AWS hint)
[ "$AWS_HINT" = "true" ] && MANIFEST_ITEMS=$(echo $MANIFEST_ITEMS | jq '. + [{"id":"m07","tool":"trufflehog_aws","target":"all_surfaces","reason":"AWS detected in tech stack - hunt AKIA/ASIA keys specifically","priority":"MUST","status":"pending"}]')

# M08: GitHub dorking (SHOULD)
MANIFEST_ITEMS=$(echo $MANIFEST_ITEMS | jq '. + [{"id":"m08","tool":"github_dorking","target":"github.com","reason":"Manual dorks find what automated scans miss","priority":"SHOULD","status":"pending"}]')

# M09: Wayback/Archive secret hunting (SHOULD - old JS versions)
MANIFEST_ITEMS=$(echo $MANIFEST_ITEMS | jq '. + [{"id":"m09","tool":"wayback_js","target":"archived_js","reason":"Old JS versions often contain deleted-but-committed secrets","priority":"SHOULD","status":"pending"}]')

# Write manifest to session.json
jq --argjson items "$MANIFEST_ITEMS" \
  '.scalpel.active_manifest = {"phase":"secrets","generated_at":"'"$(date '+%Y-%m-%d %H:%M')"'","items":$items}' \
  $SESSION > /tmp/s.json && mv /tmp/s.json $SESSION

echo "=== EXECUTION MANIFEST GENERATED ==="
jq '.scalpel.active_manifest.items[] | "[\(.priority)] \(.id): \(.tool) on \(.target)"' $SESSION
echo ""
```

---

## Phase 2: Execute Manifest — TruffleHog on JS Bundles (M01)

**Run on the SPECIFIC JS bundle URLs found in recon. Not on the domain generically.**

```bash
mkdir -p $RESULTS/secrets/js-bundles

# Download each discovered JS bundle and scan it
echo "$JS_BUNDLES" | while read URL; do
  [ -z "$URL" ] && continue
  FILENAME=$(echo $URL | md5sum | cut -d' ' -f1).js
  curl -sk "$URL" -o "$RESULTS/secrets/js-bundles/$FILENAME" 2>/dev/null
  echo "$URL -> $FILENAME" >> $RESULTS/secrets/js-url-map.txt
done

# TruffleHog on downloaded JS files
trufflehog filesystem $RESULTS/secrets/js-bundles/ \
  --only-verified \
  --json 2>/dev/null | tee $RESULTS/secrets/trufflehog-js.json

# Also scan any JS files recon already downloaded
[ -d $RESULTS/recon/js/files/ ] && \
  trufflehog filesystem $RESULTS/recon/js/files/ \
    --only-verified \
    --json 2>/dev/null | tee -a $RESULTS/secrets/trufflehog-js.json

# SecretFinder as backup (regex-based, catches patterns TruffleHog misses)
python3 ~/tools/SecretFinder/SecretFinder.py \
  -i $RESULTS/secrets/js-bundles/ \
  -o $RESULTS/secrets/secretfinder-js.txt 2>/dev/null

echo "[M01] TruffleHog JS scan: $(cat $RESULTS/secrets/trufflehog-js.json 2>/dev/null | jq 'select(.Verified==true)' | wc -l) verified secrets"

# Check off M01
jq '(.scalpel.active_manifest.items[] | select(.id=="m01")).status = "done"' $SESSION > /tmp/s.json && mv /tmp/s.json $SESSION
```

---

## Phase 3: Execute Manifest — TruffleHog GitHub Org (M02)

**Scan the SPECIFIC GitHub org(s) found during recon.**

```bash
mkdir -p $RESULTS/secrets/github

echo "$GITHUB_ORGS" | while read ORG; do
  [ -z "$ORG" ] && continue
  echo "[M02] Scanning GitHub org: $ORG"

  # TruffleHog verified scan
  trufflehog github \
    --org=$ORG \
    --only-verified \
    --json 2>/dev/null | tee $RESULTS/secrets/github/trufflehog-$ORG-verified.json

  # Deleted commits / force-pushed history
  trufflehog github \
    --org=$ORG \
    --include-unverified \
    --since-commit HEAD~2000 \
    --json 2>/dev/null | tee $RESULTS/secrets/github/trufflehog-$ORG-history.json

  echo "[M02] Org $ORG: $(cat $RESULTS/secrets/github/trufflehog-$ORG-verified.json 2>/dev/null | jq 'select(.Verified==true)' | wc -l) verified"
done

# If no org found: scan target domain on GitHub
[ -z "$GITHUB_ORGS" ] && echo "[M02] No org found in recon - falling back to domain search" && \
  trufflehog github --repo=https://github.com --json 2>/dev/null | grep -i $TARGET | head -20

jq '(.scalpel.active_manifest.items[] | select(.id=="m02")).status = "done"' $SESSION > /tmp/s.json && mv /tmp/s.json $SESSION
```

---

## Phase 4: Execute Manifest — Gitleaks (M03)

```bash
# Gitleaks on all downloaded GitHub content
gitleaks detect \
  --source=$RESULTS/secrets/github/ \
  -v --report-format json \
  --report-path=$RESULTS/secrets/gitleaks.json 2>/dev/null

# Also on JS bundles (different regex patterns)
gitleaks detect \
  --source=$RESULTS/secrets/js-bundles/ \
  -v --report-format json \
  --report-path=$RESULTS/secrets/gitleaks-js.json 2>/dev/null

echo "[M03] Gitleaks: $(cat $RESULTS/secrets/gitleaks.json 2>/dev/null | jq 'length') findings"

jq '(.scalpel.active_manifest.items[] | select(.id=="m03")).status = "done"' $SESSION > /tmp/s.json && mv /tmp/s.json $SESSION
```

---

## Phase 5: Execute Manifest — Postman Collection Hunt (M04)

**This is the one most commonly skipped. Run it every time.**

```bash
mkdir -p $RESULTS/secrets/postman

# Search Postman public workspace for target
TARGET_BASE=$(echo $TARGET | sed 's/\..*//')

echo "[M04] Searching Postman for: $TARGET / $TARGET_BASE"

# Method 1: Postman's public search (requires API key or browser)
# Direct API check
curl -s "https://www.postman.com/explore/search?q=$TARGET&type=workspace" 2>/dev/null | \
  grep -oE '"uid":"[^"]+"|"name":"[^"]+"' | head -20 \
  > $RESULTS/secrets/postman/postman-search.txt

# Method 2: Search GitHub for Postman collection files containing target
gh search code "$TARGET postman_collection" --extension=json 2>/dev/null | head -20 | \
  tee $RESULTS/secrets/postman/github-postman.txt

# Method 3: Search for target.com in published Postman collections
curl -s "https://www.postman.com/search?q=$TARGET" 2>/dev/null | \
  grep -oE "https://www\.postman\.com/[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+" | sort -u | head -10 \
  > $RESULTS/secrets/postman/collections-found.txt

# If collections found: download and scan for secrets
cat $RESULTS/secrets/postman/collections-found.txt | while read URL; do
  curl -s "$URL/json" 2>/dev/null | \
    grep -oE '"value":"[^"]*AKIA[^"]*"|"value":"[^"]*Bearer [^"]*"' | head -10
done | tee $RESULTS/secrets/postman/postman-secrets.txt

echo "[M04] Postman: $(wc -l < $RESULTS/secrets/postman/collections-found.txt) collections found"

jq '(.scalpel.active_manifest.items[] | select(.id=="m04")).status = "done"' $SESSION > /tmp/s.json && mv /tmp/s.json $SESSION
```

---

## Phase 6: Execute Manifest — API Spec + Config File Hunt (M05, M06)

**Run on EACH live host from the intel relay, not just the main domain.**

```bash
mkdir -p $RESULTS/secrets/api-specs

# ── API Spec hunting ─────────────────────────────────────────────────────────
API_PATHS="/swagger.json /swagger/v1/swagger.json /api-docs /api/swagger.json \
  /v1/api-docs /openapi.json /docs/swagger.json /swagger-ui.html \
  /.well-known/openapi.json /api/v1/swagger.json /api/v2/swagger.json \
  /graphql /api/graphql /__graphql /api/v1/graphql"

echo "$LIVE_HOSTS" | while read HOST; do
  [ -z "$HOST" ] && continue
  for PATH in $API_PATHS; do
    RESPONSE=$(curl -sk "https://${HOST}${PATH}" -w "HTTPCODE:%{http_code}" 2>/dev/null)
    CODE=$(echo $RESPONSE | grep -oE "HTTPCODE:[0-9]+" | cut -d: -f2)
    BODY=$(echo $RESPONSE | sed 's/HTTPCODE:[0-9]*//')

    if [[ "$CODE" == "200" ]] && echo "$BODY" | python3 -c "import json,sys; d=json.load(sys.stdin); exit(0 if ('paths' in d or 'openapi' in d or 'swagger' in d or '__schema' in str(d)) else 1)" 2>/dev/null; then
      echo "[API SPEC] FOUND: https://${HOST}${PATH}"
      echo "$BODY" > $RESULTS/secrets/api-specs/${HOST//\//-}${PATH//\//-}.json
      # Extract all endpoints and write to session intel
      ENDPOINTS=$(echo "$BODY" | python3 -c "import json,sys; d=json.load(sys.stdin); [print(k) for k in d.get('paths',{}).keys()]" 2>/dev/null | jq -R . | jq -s .)
      jq --argjson eps "$ENDPOINTS" '.intel.endpoints += $eps | .intel.endpoints |= unique' $SESSION > /tmp/s.json && mv /tmp/s.json $SESSION
    fi
  done
done

jq '(.scalpel.active_manifest.items[] | select(.id=="m05")).status = "done"' $SESSION > /tmp/s.json && mv /tmp/s.json $SESSION

# ── .env + config file hunting ───────────────────────────────────────────────
ENV_PATHS="/.env /.env.production /.env.local /.env.backup /config.yaml /config.json \
  /docker-compose.yml /docker-compose.yaml /.git/config /.htpasswd \
  /wp-config.php /configuration.php /settings.py /application.properties"

echo "$LIVE_HOSTS" | while read HOST; do
  [ -z "$HOST" ] && continue
  for PATH in $ENV_PATHS; do
    CODE=$(curl -sk -o /tmp/env_test.txt -w "%{http_code}" "https://${HOST}${PATH}" 2>/dev/null)
    SIZE=$(wc -c < /tmp/env_test.txt 2>/dev/null || echo 0)

    # Real .env: 200 + non-empty + not HTML
    if [[ "$CODE" == "200" && "$SIZE" -gt 50 ]] && ! grep -qi "<!DOCTYPE\|<html" /tmp/env_test.txt 2>/dev/null; then
      echo "[ENV FILE] FOUND: https://${HOST}${PATH} (${SIZE} bytes)"
      cp /tmp/env_test.txt $RESULTS/secrets/${HOST//\//-}${PATH//\//-}.txt
      # Scan immediately for secrets
      trufflehog filesystem /tmp/env_test.txt --only-verified --json 2>/dev/null | tee -a $RESULTS/secrets/trufflehog-env.json
    fi
  done
done

jq '(.scalpel.active_manifest.items[] | select(.id=="m06")).status = "done"' $SESSION > /tmp/s.json && mv /tmp/s.json $SESSION
```

---

## Phase 7: Execute Manifest — AWS-Specific Hunt (M07, conditional)

**Only runs if `AWS_HINT=true` from recon intel relay. But when it does run, it's thorough.**

```bash
if [ "$AWS_HINT" = "true" ]; then
  echo "[M07] AWS detected - running targeted key hunt"
  mkdir -p $RESULTS/secrets/aws

  # Pattern: AKIA (long-term access key), ASIA (temp STS token)
  # Scan ALL collected files for AWS key patterns
  grep -rh "AKIA[0-9A-Z]\{16\}\|ASIA[0-9A-Z]\{16\}" \
    $RESULTS/secrets/ $RESULTS/recon/js/files/ 2>/dev/null | \
    head -20 > $RESULTS/secrets/aws/aws-keys-found.txt

  # TruffleHog with AWS detector specifically
  trufflehog filesystem $RESULTS/ \
    --detector=AWS \
    --only-verified \
    --json 2>/dev/null | tee $RESULTS/secrets/aws/trufflehog-aws.json

  # Check environment variable leaks in responses
  echo "$LIVE_HOSTS" | while read HOST; do
    [ -z "$HOST" ] && continue
    # Some apps leak env vars in debug endpoints
    for DEBUG in /actuator/env /debug/vars /__debug/vars /api/debug /api/config /api/env; do
      curl -sk "https://${HOST}${DEBUG}" 2>/dev/null | \
        grep -i "AWS_\|ACCESS_KEY\|SECRET_KEY" | head -5
    done
  done | tee $RESULTS/secrets/aws/env-endpoints.txt

  AWS_KEYS=$(cat $RESULTS/secrets/aws/aws-keys-found.txt 2>/dev/null | wc -l)
  echo "[M07] AWS keys found: $AWS_KEYS"

  jq '(.scalpel.active_manifest.items[] | select(.id=="m07")).status = "done"' $SESSION > /tmp/s.json && mv /tmp/s.json $SESSION
fi
```

---

## Phase 8: Execute Manifest — GitHub Dorking (M08)

**Manual dorks that automated scanners miss. These run against github.com search, not the org.**

```bash
mkdir -p $RESULTS/secrets/github-dorks

cat > $RESULTS/secrets/github-dorks/dorks.txt << EOF
"$TARGET" password
"$TARGET" api_key
"$TARGET" secret_key
"$TARGET" token
"$TARGET" "-----BEGIN RSA PRIVATE KEY-----"
"$TARGET" "AKIA" OR "ASIA"
"$TARGET" aws_access_key_id
"$TARGET" filename:.env
"$TARGET" filename:config.yaml OR filename:config.json
"$TARGET" filename:docker-compose.yml
"$TARGET" jdbc:// OR mongodb:// OR postgres://
"$TARGET" "client_secret" OR "client_id"
EOF

# Run automated dork search if gh CLI available
while IFS= read -r DORK; do
  [[ "$DORK" == \#* ]] && continue
  echo "Searching: $DORK"
  gh search code "$DORK" --json path,repository --limit 5 2>/dev/null | \
    jq -r '.[] | "\(.repository.full_name): \(.path)"' | \
    tee -a $RESULTS/secrets/github-dorks/results.txt
done < $RESULTS/secrets/github-dorks/dorks.txt

echo "[M08] GitHub dork results: $(wc -l < $RESULTS/secrets/github-dorks/results.txt 2>/dev/null)"

jq '(.scalpel.active_manifest.items[] | select(.id=="m08")).status = "done"' $SESSION > /tmp/s.json && mv /tmp/s.json $SESSION
```

---

## Phase 9: Execute Manifest — Wayback/Archive JS Hunt (M09)

**Old JS versions = deleted secrets that were once committed. Frequently overlooked.**

```bash
mkdir -p $RESULTS/secrets/wayback-js

# Get archived JS URLs for live hosts
echo "$LIVE_HOSTS" | head -5 | while read HOST; do
  [ -z "$HOST" ] && continue
  DOMAIN=$(echo $HOST | sed 's|https\?://||' | cut -d/ -f1)
  curl -s "https://web.archive.org/cdx/search/cdx?url=${DOMAIN}/*.js&output=json&fl=timestamp,original&filter=statuscode:200&collapse=original&limit=100" 2>/dev/null | \
    jq -r '.[] | "https://web.archive.org/web/\(.[0])/\(.[1])"' | \
    head -30
done | sort -u > $RESULTS/secrets/wayback-js/wayback-js-urls.txt

# Download and scan archived JS files
cat $RESULTS/secrets/wayback-js/wayback-js-urls.txt | while read URL; do
  FILENAME=$(echo $URL | md5sum | cut -d' ' -f1).js
  curl -sk "$URL" -o "$RESULTS/secrets/wayback-js/$FILENAME" 2>/dev/null
done

# TruffleHog on archived JS
trufflehog filesystem $RESULTS/secrets/wayback-js/ \
  --only-verified \
  --json 2>/dev/null | tee $RESULTS/secrets/trufflehog-wayback.json

echo "[M09] Archived JS scanned: $(ls $RESULTS/secrets/wayback-js/*.js 2>/dev/null | wc -l)"
echo "[M09] Archived JS secrets: $(cat $RESULTS/secrets/trufflehog-wayback.json 2>/dev/null | jq 'select(.Verified==true)' | wc -l) verified"

jq '(.scalpel.active_manifest.items[] | select(.id=="m09")).status = "done"' $SESSION > /tmp/s.json && mv /tmp/s.json $SESSION
```

---

## Phase 10: Completion Gate + Intel Relay

```bash
# ── COMPLETION GATE ──────────────────────────────────────────────────────────
PENDING_MUST=$(jq '[.scalpel.active_manifest.items[] | select(.priority=="MUST" and .status=="pending")] | length' $SESSION 2>/dev/null || echo 0)

if [ "$PENDING_MUST" -gt 0 ]; then
  echo "=== COMPLETION GATE BLOCKED: $PENDING_MUST MUST items still pending ==="
  jq '.scalpel.active_manifest.items[] | select(.priority=="MUST" and .status=="pending") | "[ ] \(.id): \(.tool) on \(.target)"' $SESSION
  echo ""
  echo "Run the missing items above before proceeding. Each must be explicitly completed or skipped with reason."
  # Stop here - do not proceed to write interesting_secrets.md
  exit 1
fi

# ── Aggregate all verified secrets ───────────────────────────────────────────
ALL_VERIFIED=$(cat \
  $RESULTS/secrets/trufflehog-js.json \
  $RESULTS/secrets/github/trufflehog-*-verified.json \
  $RESULTS/secrets/trufflehog-env.json \
  $RESULTS/secrets/aws/trufflehog-aws.json \
  $RESULTS/secrets/trufflehog-wayback.json \
  2>/dev/null | jq -s 'flatten | map(select(.Verified==true))')

CRED_COUNT=$(echo "$ALL_VERIFIED" | jq 'length')

# ── Emit signals ─────────────────────────────────────────────────────────────
AWS_KEY_FOUND=$(echo "$ALL_VERIFIED" | jq '[.[] | select(.DetectorName=="AWS")] | length')
JWT_FOUND=$(cat $RESULTS/secrets/secretfinder-js.txt 2>/dev/null | grep -i "eyJ" | wc -l)

[ "$CRED_COUNT" -gt 0 ] && echo "[SIGNAL] CRED_FOUND: $CRED_COUNT verified credentials"
[ "$AWS_KEY_FOUND" -gt 0 ] && echo "[SIGNAL] CRED_FOUND(AWS) + TECH_DETECTED(AWS) → fork /cloud-audit immediately (priority: 95)"
[ "$JWT_FOUND" -gt 0 ] && echo "[SIGNAL] JWT_FOUND → boost JWT confusion hypothesis +15%"

# ── Write intel relay for exploit phase ──────────────────────────────────────
VERIFIED_CREDS_JSON=$(echo "$ALL_VERIFIED" | jq 'map({type: .DetectorName, value: (.Raw // "" | .[:40]), source: .SourceMetadata.Data.Filesystem.file, tested: false})')
API_ENDPOINTS_JSON=$(jq '.intel.endpoints // []' $SESSION 2>/dev/null)
JWT_TOKENS_JSON=$(cat $RESULTS/secrets/secretfinder-js.txt 2>/dev/null | grep -oE "eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+" | sort -u | jq -R . | jq -s . || echo "[]")

jq --argjson creds "$VERIFIED_CREDS_JSON" \
   --argjson eps "$API_ENDPOINTS_JSON" \
   --argjson jwts "$JWT_TOKENS_JSON" \
   --argjson aws "$([ $AWS_KEY_FOUND -gt 0 ] && echo true || echo false)" \
   '.intel_relay.from_secrets = {
     "verified_credentials": $creds,
     "api_spec_endpoints": $eps,
     "jwt_tokens": $jwts,
     "aws_keys_found": $aws,
     "github_secrets_found": false,
     "postman_collections": []
   } |
   .intel.credentials = $creds |
   .intel.jwt_tokens = $jwts |
   .threads[0].phase = "exploit"' \
   $SESSION > /tmp/s.json && mv /tmp/s.json $SESSION

# Increment SNR
jq '.scalpel.snr.tool_runs += 9 | .scalpel.snr.signals_emitted += '"$([ $CRED_COUNT -gt 0 ] && echo 1 || echo 0)" \
  $SESSION > /tmp/s.json && mv /tmp/s.json $SESSION

# ── Write interesting_secrets.md ──────────────────────────────────────────────
cat > $RESULTS/interesting_secrets.md << EOF
## Status
$([ $CRED_COUNT -gt 0 ] && echo "findings-present" || echo "no-findings")

## Summary
Target: $TARGET | Verified secrets: $CRED_COUNT | AWS keys: $AWS_KEY_FOUND | JWTs: $JWT_FOUND
Manifest completed: $(jq '[.scalpel.active_manifest.items[] | select(.status=="done")] | length' $SESSION)/$(jq '.scalpel.active_manifest.items | length' $SESSION) items

## Verified Secrets
$(echo "$ALL_VERIFIED" | jq -r '.[] | "- [CONFIRMED] \(.DetectorName) in \(.SourceMetadata.Data.Filesystem.file // "github") — \(.Raw[:50])"' 2>/dev/null)

## API Specs Found
$(ls $RESULTS/secrets/api-specs/*.json 2>/dev/null | while read F; do echo "- $F ($(cat $F | jq '.paths | keys | length') endpoints)"; done)

## Raw Evidence
- TruffleHog JS: $RESULTS/secrets/trufflehog-js.json
- TruffleHog GitHub: $RESULTS/secrets/github/
- TruffleHog Wayback: $RESULTS/secrets/trufflehog-wayback.json
- Gitleaks: $RESULTS/secrets/gitleaks.json
- API Specs: $RESULTS/secrets/api-specs/
- Postman: $RESULTS/secrets/postman/
EOF

echo ""
echo "Secrets phase complete."
echo "Verified secrets: $CRED_COUNT"
echo "AWS key found: $([ $AWS_KEY_FOUND -gt 0 ] && echo 'YES - fork /cloud-audit immediately' || echo 'no')"
echo "Run /exploit $TARGET for phase 3."
```
