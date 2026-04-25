# Recon Step 11: GitHub / GitLab Dorking + Secret Scanning

In 2024, 23.8 million secrets were leaked on GitHub - 39 million total across the platform. Orgs accidentally push API keys, internal hostnames, and credentials to public repos constantly.

```bash
TARGET="target.com"
ORG="targetorg"   # GitHub org name
RESULTS=~/pentest-toolkit/results/$TARGET
mkdir -p $RESULTS/recon/github

# TruffleHog - scan entire GitHub organization for verified secrets
# Verified = TruffleHog actually tested the credential against the API
trufflehog github \
  --org=$ORG \
  --only-verified \
  --json 2>/dev/null | tee $RESULTS/recon/github/trufflehog-org.json

# Scan for deleted commits / force-pushed history (GitHub keeps these)
trufflehog github \
  --org=$ORG \
  --include-unverified \
  --since-commit HEAD~1000 \
  --json 2>/dev/null | tee $RESULTS/recon/github/trufflehog-history.json

# GitLeaks - fast regex-based scanning for common secret patterns
gitleaks detect \
  --source=$RESULTS/recon/github/ \
  -v --report-format json \
  --report-path=$RESULTS/recon/github/gitleaks.json 2>/dev/null
```

## Manual GitHub Dorks

Run these at github.com/search:

```bash
cat << EOF > $RESULTS/recon/github/dorks.txt
# Secrets
"$TARGET" password
"$TARGET" api_key
"$TARGET" secret_key
"$TARGET" token
"$TARGET" credentials
"$TARGET" "-----BEGIN RSA PRIVATE KEY-----"
"$TARGET" aws_access_key_id
"$TARGET" "AKIA" OR "ASIA"

# Internal infrastructure
"$TARGET" internal hostname
"$TARGET" staging dev
"$TARGET" jdbc:// OR mongodb:// OR postgres://

# Config files
"$TARGET" filename:.env
"$TARGET" filename:config.yaml OR filename:config.json
"$TARGET" filename:docker-compose.yml

# Source code with credentials
"$TARGET" language:python OR language:javascript
"@$TARGET" email
EOF

echo "[*] Verified secrets found: $(cat $RESULTS/recon/github/trufflehog-org.json | jq 'select(.Verified==true)' | wc -l)"
```

## GitLab / Self-Hosted Git

```bash
# If GitLab is detected on a subdomain (e.g., gitlab.target.com):
# API enumeration (public repos don't require auth):
curl -s "https://gitlab.$TARGET/api/v4/projects?visibility=public&per_page=100" 2>/dev/null | \
  jq -r '.[].http_url_to_repo' | while read REPO; do
    trufflehog git "$REPO" --only-verified --json 2>/dev/null
  done | tee $RESULTS/recon/github/gitlab-secrets.json

# Gitleaks on cloned repos:
git clone --depth=1 "$REPO" /tmp/repo_scan 2>/dev/null
gitleaks detect --source=/tmp/repo_scan --report-format json \
  --report-path=$RESULTS/recon/github/gitleaks-gitlab.json 2>/dev/null
rm -rf /tmp/repo_scan
```

**Signal:** `emit_signal CRED_FOUND "GitHub secret verified: <DetectorName> in <RepoName>" "main/recon" 0.95`
