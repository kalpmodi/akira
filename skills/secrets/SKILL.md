---
name: secrets
description: Use when hunting for secrets, API keys, tokens, or credentials on a pentest target, running phase 2 of an engagement, scanning JS files for hardcoded secrets, or running trufflehog/gitleaks. Also use when the user says "run secrets", "hunt secrets", or "phase 2".
---

# Secrets Hunting Phase

## Overview
Runs secrets hunting toolkit with recon-provided scope (if available) and summarizes verified findings into `interesting_secrets.md`.

---

## Session Intelligence Protocol

**Read before scanning:**

```bash
SESSION=~/pentest-toolkit/results/<target>/session.json
STATE=$(cat $SESSION 2>/dev/null | jq -r '.engagement_state // "WIDE"')
HYPS=$(cat $SESSION 2>/dev/null | jq -r '.hypotheses[] | select(.status=="active") | "\(.id)[\((.probability*100)|round)%] \(.label)"' 2>/dev/null)
KNOWN_ENDPOINTS=$(cat $SESSION 2>/dev/null | jq -r '.intel.endpoints[]?' 2>/dev/null)
KNOWN_TECH=$(cat $SESSION 2>/dev/null | jq -r '.intel.technologies[]?' 2>/dev/null | tr '\n' ',')
echo "State: $STATE | Known endpoints: $(echo $KNOWN_ENDPOINTS | wc -w)"
echo "Hypotheses: $HYPS"
```

**State machine check:**
- `HARVEST` → skip secrets scan. Evidence collection only - verify already-found credentials, don't discover new ones.
- `DEEP` → focus scanning exclusively on surfaces relevant to the active hypothesis (e.g., if H1 is SSRF→IAM, hunt for AWS keys specifically).
- `WIDE` → full scan.

**Hypothesis-driven focus:**

| Active hypothesis | Focus secrets scan on |
|---|---|
| SSRF → AWS IAM | AWS keys (AKIA/ASIA), `.env` files, docker-compose secrets |
| JWT confusion | JWT signing keys, JWKS endpoints, RS256 private keys |
| OAuth redirect | OAuth client_secret, client_id in JS/config |
| Race condition | Payment API keys, transaction tokens |
| Supply chain | Package registry tokens, CI/CD secrets in GitHub |

**Use known intel from session.json to target the scan:**
- `intel.endpoints` → scan these specific endpoints for exposed configs
- `intel.technologies` → select relevant secret patterns (Django → `SECRET_KEY`, AWS → `AKIA`, Node → `.env`)
- `intel.live_hosts` → prioritize these hosts for JS analysis

**Signal emission - emit these as you find them:**

| Discovery | Signal | Action |
|---|---|---|
| Verified secret (any) | `CRED_FOUND` (confidence: 100) | Emit immediately, check correlation |
| AWS key found | `CRED_FOUND` + `TECH_DETECTED(AWS)` | **Immediately check fork budget → spawn /cloud-audit** |
| JWT token found | `JWT_FOUND` | Boost JWT confusion hypothesis +15% |
| API key found | `CRED_FOUND` | Write to `intel.api_keys[]` |
| Internal hostname in config | `SURFACE_FOUND` | Add to `intel.internal_ips[]`, fork recon |
| API spec found (swagger/openapi) | `SURFACE_FOUND` | Write all endpoints to `intel.endpoints[]` |

**AWS key fork trigger (critical - do not skip):**
```bash
# If AWS key found in any scan result:
AWS_KEY=$(grep -r "AKIA\|ASIA" $RESULTS/secrets/ 2>/dev/null | head -1)
if [ -n "$AWS_KEY" ]; then
  echo "[SIGNAL] CRED_FOUND: AWS access key detected"
  echo "[CORRELATION] CRED_FOUND + TECH_DETECTED(AWS) → spawn /cloud-audit immediately"
  # Check fork budget and spawn cloud-audit fork if budget allows
  # Write to session.json signals[] and discovery_queue[] if budget full
fi
```

---

## Steps

1. **Get target** from user if not provided.

2. **Check for recon scope:**
   ```bash
   ls ~/pentest-toolkit/results/<target>/recon/urls.txt 2>/dev/null
   ls ~/pentest-toolkit/results/<target>/recon/live-hosts.txt 2>/dev/null
   ```
   If missing: warn "Running without recon scope — results may be noisy" and proceed.

3. **Run secrets scan with scope:**
   ```bash
   TARGET_URLS=~/pentest-toolkit/results/<target>/recon/urls.txt \
   TARGET_HOSTS=~/pentest-toolkit/results/<target>/recon/live-hosts.txt \
   ~/pentest-toolkit/secrets/secrets.sh <target>
   ```
   If exit code is non-zero: stop, invoke `superpowers:systematic-debugging`.

4. **Check for empty output:**
   ```bash
   wc -c ~/pentest-toolkit/results/<target>/secrets/trufflehog.json 2>/dev/null
   ```
   If empty or missing: write `interesting_secrets.md` with `## Status` = `no-findings`.

5. **Read and summarize — focus on verified secrets only:**
   ```bash
   cat ~/pentest-toolkit/results/<target>/secrets/trufflehog.json
   cat ~/pentest-toolkit/results/<target>/secrets/sensitive-urls.txt
   ```
   High-confidence = trufflehog `--only-verified` results, OR URL patterns with 2+ credential-like params co-present.

6. **Write `interesting_secrets.md`** to `~/pentest-toolkit/results/<target>/interesting_secrets.md`:

```markdown
## Status
findings-present

## Summary
<one paragraph: how many verified secrets, what types, where found>

## Key Findings
- [CONFIRMED] <secret type> in <location> — <brief description>
- [POTENTIAL] <pattern> in <url> — unverified credential-like parameter

## Raw Evidence References
- ~/pentest-toolkit/results/<target>/secrets/trufflehog.json
- ~/pentest-toolkit/results/<target>/secrets/sensitive-urls.txt
```

7. **GitHub dorking for target secrets:**
   ```bash
   # Search GitHub for exposed secrets (open in browser or use gh CLI if available):
   # site:github.com "<target>" password
   # site:github.com "<target>" api_key
   # site:github.com "<target>" secret
   # site:github.com "<target>" token
   # site:github.com "<target>" DB_PASSWORD

   # If gh CLI available:
   gh search code "<target> password" --language='' 2>/dev/null | head -20
   gh search code "<target> api_key OR secret OR token" 2>/dev/null | head -20
   ```

8. **API spec / Postman collection hunting:**
   ```bash
   # Swagger/OpenAPI docs (often exposed in prod):
   for path in /swagger.json /swagger/v1/swagger.json /api-docs /api/swagger.json \
               /v1/api-docs /openapi.json /docs/swagger.json /swagger-ui.html \
               /.well-known/openapi.json /api/v1/swagger.json /api/v2/swagger.json; do
     curl -sk "https://<target>$path" -o /tmp/swagger_test.json 2>/dev/null
     if python3 -c "import json,sys; d=json.load(open('/tmp/swagger_test.json')); print('FOUND' if 'paths' in d or 'openapi' in d or 'swagger' in d else 'NO')" 2>/dev/null | grep -q FOUND; then
       echo "API SPEC FOUND at: https://<target>$path"
       cp /tmp/swagger_test.json ~/pentest-toolkit/results/<target>/secrets/api_spec.json
     fi
   done

   # Postman collection leaks (check GitHub search above for .postman_collection.json)
   # Also check: /api/postman, /postman-collection.json, /collection.json
   ```
   If API spec found: extract all endpoints and add to intel for exploit phase.

9. **Phase-End Protocol - write back to session.json:**

```bash
SESSION=~/pentest-toolkit/results/<target>/session.json
RESULTS=~/pentest-toolkit/results/<target>

# Write all verified credentials to intel
CREDS=$(cat $RESULTS/secrets/trufflehog.json 2>/dev/null | \
  jq -c '[.[] | select(.Verified==true) | {type: .DetectorName, value: .Raw[:40], source: .SourceMetadata.Data.Filesystem.file, tested: false}]')

# Write API keys, JWT tokens separately
API_KEYS=$(grep -rh "AKIA\|sk-\|Bearer " $RESULTS/secrets/ 2>/dev/null | head -20 | jq -R . | jq -s .)

jq --argjson creds "${CREDS:-[]}" \
   --argjson keys "${API_KEYS:-[]}" \
   '.intel.credentials = $creds | .intel.api_keys = $keys | .threads[0].phase = "exploit"' \
   $SESSION > /tmp/s.json && mv /tmp/s.json $SESSION

# Emit signals for each verified credential
echo "Emitting CRED_FOUND signals for verified credentials..."

# Calibrate hypotheses:
# - AWS key found → boost cloud-audit hypothesis to 95%
# - JWT found → boost JWT confusion hypothesis +15%
# - OAuth secret found → boost OAuth redirect hypothesis +20%

# Check fork opportunities:
[ -n "$(grep -r 'AKIA\|ASIA' $RESULTS/secrets/ 2>/dev/null | head -1)" ] && \
  echo "[FORK] AWS key confirmed → cloud-audit fork (priority: 95)"

[ -s $RESULTS/secrets/api_spec.json ] && \
  echo "[INTEL] API spec found → writing endpoints to session.json intel.endpoints[]"
```

10. Tell the user: "Secrets hunt complete. `interesting_secrets.md` written. Run `/exploit <target>` for phase 3."
