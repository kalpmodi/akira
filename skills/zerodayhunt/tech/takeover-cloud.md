# ZDH Phase 11, 12: Subdomain Takeover + Cloud Asset Enumeration

## Phase 11 - Subdomain Takeover

**Goal:** Find dangling CNAMEs pointing to unclaimed cloud resources.

```bash
# For every CNAME record found in recon:
dig +short <subdomain>.<target>

# If CNAME points to:
# *.github.io            -> check if GitHub Pages repo exists
# *.herokuapp.com        -> check if Heroku app exists
# *.azurewebsites.net    -> check if Azure app exists
# *.s3.amazonaws.com     -> check if S3 bucket exists (GET request)
# *.pantheonsite.io      -> check if Pantheon site exists
# *.fastly.net           -> check if Fastly service claimed
# *.shopify.com          -> check if Shopify store exists
# *.zendesk.com          -> check if Zendesk account exists

# Test S3 bucket takeover:
curl -I https://<subdomain>.<target>.com
# If response: "NoSuchBucket" or "InvalidBucketName" -> UNCLAIMED bucket

# Test GitHub Pages:
# If CNAME -> orgname.github.io, check if github.com/<orgname>/<repo> exists
# If not -> create repo, publish to Pages, you now control that subdomain

# Automated check:
nuclei -t takeovers/ -u https://<subdomain>.<target>

# Impact: host phishing page, steal OAuth tokens via redirect, XSS on target domain
```

## Phase 12 - Cloud Asset Enumeration

**Goal:** Find exposed S3/GCS buckets, Lambda URLs, misconfigured cloud storage.

```bash
# S3 bucket enumeration (generate names from target brand)
# Replace <brand> with target company name and common variations
for name in <brand> <brand>corp <brand>-static <brand>-media <brand>-backup \
            <brand>-prod <brand>-dev <brand>-logs <brand>-assets <brand>-uploads; do
  curl -s "https://${name}.s3.amazonaws.com/" | grep -q "NoSuchBucket\|ListBucket" && echo "FOUND: $name"
done

# GCS bucket
for name in <brand> <brand>corp <brand>-static <brand>-cdn; do
  curl -s "https://storage.googleapis.com/${name}/" | grep -q "NoSuchBucket\|AccessDenied" && echo "FOUND: $name"
done

# AWS Lambda function URLs (unauthenticated by default if misconfigured)
# Pattern: https://<id>.lambda-url.<region>.on.aws/
# Found via: JS bundle, GitHub Actions workflow logs

# AWS Cognito misconfiguration
# Check identity pool in JS: AWS.config.region + IdentityPoolId
# If found: can get temporary IAM credentials via unauthenticated identity
aws cognito-identity get-id --account-id <id> --identity-pool-id <pool-id> --region <region>
aws cognito-identity get-credentials-for-identity --identity-id <id> --region <region>
# Temporary AWS creds = enumerate S3, DynamoDB, etc.

# S3 misconfig checks (if bucket found):
curl "https://<bucket>.s3.amazonaws.com/?list-type=2"  # list files
# Check for: db dumps, backup files, logs with user data, env files
```

**Signal:** `emit_signal SURFACE_FOUND "Subdomain takeover: <subdomain> -> <unclaimed-service>" "main/zerodayhunt" 0.90`
