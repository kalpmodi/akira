# ZDH Phase 4-5, 18: GitHub Deep Scan + JS Bundle Analysis + Source Map Exposure

## Phase 4 - GitHub Organization Deep Scan

**Goal:** Find hardcoded credentials, internal endpoints, encryption keys.

```python
# 1. List all public repos
GET https://api.github.com/orgs/<org>/repos?per_page=100&type=public

# 2. For each repo - get full file tree
GET https://api.github.com/repos/<org>/<repo>/git/trees/main?recursive=1

# 3. Priority files (highest credential density):
# - src/test/java/**/*Tests*.java  <- test creds = REAL creds for test env (proven technique)
# - demo/*, examples/*, sample/*
# - .github/workflows/*.yml        <- CI/CD secrets exposure (see Phase 22)
# - *.properties, *.yml, *.env

# 4. Keys to find:
# openKeyId, secretKey, appid, appSecret, password, token, key,
# AccessKeyId, SecretAccessKey, private_key, client_secret, GITHUB_TOKEN

# 5. Check ALL branches (dev, staging, feature/* branches have more secrets)
GET https://api.github.com/repos/<org>/<repo>/branches

# 6. Check DELETED secrets in git history
GET https://api.github.com/repos/<org>/<repo>/commits?per_page=100
# For suspicious commits (message: "remove key", "fix config"):
GET https://api.github.com/repos/<org>/<repo>/commits/<sha>
# Check the diff for what was removed
```

**Live credential test:**
```bash
# Test leaked API key immediately:
curl -s "https://api.<target>/endpoint" \
  -H "Authorization: Bearer <found_token>"
# HTTP 200 with data = CONFIRMED LIVE
# HTTP 401 = expired/revoked (still report as CRED-STALE)
```

**Classify:**
- `[CRED-LIVE]` = tested against live server, returns 200 with data
- `[CRED-STALE]` = returns 401/403 on live server
- `[ENDPOINT]` = new internal API path discovered
- `[KEY]` = encryption/signing key
- `[INTERNAL-NS]` = internal package namespace (input to supply-chain.md)

## Phase 5 - JavaScript Bundle Analysis

**Goal:** Lazy-loaded chunks contain ALL real endpoints. Main bundle = nothing.
Scanners never fetch webpack chunks. This is a reliable zero-scanner finding.

```python
import re, requests

# Step 1: Get webpack manifest (maps chunk IDs to hashes)
r = requests.get("https://<target>/", headers={"User-Agent": "Mozilla/5.0"})
# Find manifest: manifest.abc123.bundle.js OR runtime~main.abc.js
manifest_matches = re.findall(r'"(/[^"]*manifest[^"]*\.js)"', r.text)

# Step 2: Parse chunk ID -> hash mapping from manifest
manifest_js = requests.get("https://<target>" + manifest_url).text
hashes = re.findall(r'"([a-f0-9]{8,})"', manifest_js)  # extract all chunk hashes

# Step 3: Guess chunk names (these are common in enterprise apps)
chunk_names = ["home", "dashboard", "admin", "chart", "order", "monitor",
               "index", "user", "setting", "report", "alert", "config",
               "finance", "supplier", "warehouse", "ops", "risk"]
for name in chunk_names:
    for h in hashes:
        r = requests.get(f"https://<target>/static/js/{name}.{h}.chunk.js")
        if r.status_code == 200 and len(r.text) > 1000:
            # Extract patterns
            for pat in [r'url:"(/[^"]+)"', r'\.get\("(/[^"]+)"', r'\.post\("(/[^"]+)"',
                        r'path:"(/[^"]+)"', r'endpoint:"(/[^"]+)"']:
                print(re.findall(pat, r.text))

# Step 4: Also extract from bundle:
# - Internal hostnames: re.findall(r'[\w.-]+\.internal|[\w.-]+\.corp', js)
# - Auth header names (reveals signing scheme)
# - SSO URLs in auth error message strings
# - Encryption keys in constants
# - CI_COMMIT_SHA (maps to git history for secret hunting)
```

**Test discovered endpoints without auth first:**
```bash
curl -s "https://<target>/web/alert/query" -X POST -H "Content-Type: application/json" -d '{}'
# JSON 400/500 = endpoint past WAF = FINDING even if auth required
# {"code":400106,"message":"Non-SSO login not allowed"} = endpoint exists + SSO hostname leaked
```

## Phase 18 - Source Map & Build Artifact Exposure

```bash
# For each JS bundle URL:
curl https://<target>/static/js/main.abc123.chunk.js.map  # webpack source map

# Common paths:
/_next/static/chunks/pages/*.js.map   # Next.js
/assets/index.js.map                  # Vite
/static/js/*.js.map                   # CRA

# Source maps contain ORIGINAL unminified TypeScript/JSX source code
# In source map: look for hardcoded keys, internal comments, TODO: security issues

# Git exposure:
curl https://<target>/.git/config     # confirms git repo, remote URL
curl https://<target>/.git/HEAD       # current branch name
curl https://<target>/.git/COMMIT_EDITMSG  # last commit message
# Use tool: git-dumper to download entire repo if exposed

# Other artifacts:
curl https://<target>/.env
curl https://<target>/config.js
curl https://<target>/api-docs.json
curl https://<target>/swagger.json
curl https://<target>/graphql -d '{"query":"{__schema{types{name}}}"}'

# Build metadata in HTML source:
grep -i "commit\|sha\|build\|version\|git" <page_source>
# Git SHA -> find that commit in public repo -> check removed secrets in diff
```
