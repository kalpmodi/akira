---
name: zerodayhunt
description: Use when hunting for zero-days, backdoors, RCE, supply chain attacks, JWT vulnerabilities, cache poisoning, HTTP smuggling, dependency confusion, source map exposure, GSRM/WAF bypass, internal admin panel exposure, business logic flaws, race conditions, subdomain takeover, cloud misconfigs, mobile APK secrets, OAuth attacks, CORS misconfigs, serialization/SSTI/XXE, CI/CD pipeline attacks, or chained attack vectors. Also use when user says "find zero day", "hunt backdoor", "find RCE", "go deep", "maximum potential", "find critical", "chain attack", or "elite hunt".
---

# Zero-Day & Critical Vulnerability Hunt

## Philosophy
Automated tools find known CVEs. This skill finds what scanners miss:
logic flaws, architecture leaks, supply chain vectors, auth bypasses,
and chained attacks. Evidence required before claiming ANY finding.
Never hallucinate - if you didn't see it in a response body, it didn't happen.

**The rule that separates elite from script kiddie:** A single finding is rarely Critical.
The payout comes from CHAINING. SSRF + AWS metadata = IAM creds = cloud takeover.
Info disclosure + IDOR = mass PII = Critical. Always ask: "What can I do WITH this?"

**Critical rule:** NEVER stop at "SSRF/network reachability possible" or "endpoint exists".
Must prove full chain: credentials extracted, PII accessed, or data exfiltrated.
A 200 with empty body = WAF catch-all, not a real finding.

## ARGUMENTS
`<target>` - domain (e.g. target.com)
`<focus>` - optional: RCE / SSRF / IDOR / SUPPLY-CHAIN / JWT / BUSINESS-LOGIC / CHAIN / ALL

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

# Aliases for downstream phase references
TECH_STACK=$KNOWN_TECH
ALL_ENDPOINTS="$INTERESTING_ENDPOINTS $WAYBACK_ENDPOINTS $API_SPEC_ENDPOINTS"
ATW_FLAGGED=$(echo "$ATW_FLAGGED" 2>/dev/null)

echo "=== ZERODAYHUNT SMART INTAKE: $TARGET ==="
echo "State: $STATE | WAF: $WAF | Tech: $TECH_STACK"
echo "Top hypothesis: $TOP_HYPO_LABEL [$TOP_HYPO_PROB%]"
echo "SSRF vectors from exploit: $(echo "$SSRF_VECTORS" | wc -l)"
echo "Internal IPs available: $(echo "$INTERNAL_IPS" | wc -w)"
echo "JWT tokens: $(echo "$JWT_TOKENS" | wc -l)"
echo "Prior confirmed findings: $(echo "$CONFIRMED_VULNS" | wc -l)"
echo "ATW flagged (skip): $ATW_FLAGGED"
echo ""
echo "Phase selection - run phases where we have targets:"
[ -n "$SSRF_VECTORS" ] && echo "  Phase 8 (SSRF): YES - $(echo "$SSRF_VECTORS" | wc -l) vectors to chain"
[ -n "$JWT_TOKENS" ] && echo "  Phase 7 (JWT): YES - tokens found"
[ -n "$INTERNAL_IPS" ] && echo "  Phase 8 (SSRF pivot): YES - internal IPs to target"
[ -n "$CONFIRMED_VULNS" ] && echo "  Phase 23 (Chain): YES - $(echo "$CONFIRMED_VULNS" | wc -l) confirmed to chain"
```

**Chain-first strategy:** Look at what's already confirmed in prior phases and ask "What can I chain WITH this?" before hunting new vectors. SSRF already confirmed + AWS detected = immediately go to IMDSv1 chain. Auth bypass confirmed = immediately check IDOR chain.

## Phase 1 - Full Context Build

- `SSRF_VECTORS` -> target these for cloud metadata chains
- `INTERNAL_IPS` -> SSRF target list for lateral movement
- `JWT_TOKENS` -> JWT confusion candidates (check alg header)
- `TECH_STACK` -> picks specific phases to prioritize (see table below)
- `VERIFIED_CREDS` -> credential spray on all surfaces before hunting new vulns
- `WAF` -> Phase 2 first if WAF present
- `ALL_ENDPOINTS` -> full attack surface for every subsequent phase

**Phase priority by tech stack:**

| Tech detected | Run these phases FIRST |
|---|---|
| AWS + SSRF_VECTOR | Phase 8 -> Phase 12 (cloud asset chain) |
| Node.js + JWT | Phase 7 (JWT confusion), Phase 25 (prototype pollution) |
| Spring Boot | Phase 15 (SSTI/deserialization), Phase 16 (CI/CD) |
| OAuth/OIDC | Phase 7 (JWT), Phase 31 (SAML/SSO) |
| GraphQL | Phase 17 (introspection, batching) |
| React/webpack | Phase 18 (source maps), Phase 5 (JS bundles) |
| any | Phase 23 (chain blueprints) - always run this last |

---

## Execution Manifest

Write to `session.json.scalpel.active_manifest` before starting:

```json
{
  "skill": "zerodayhunt",
  "target": "<target>",
  "items": [
    {"id": "zdh01", "priority": "MUST",     "tool": "waf-header-mining",  "target": "<target>", "status": "pending"},
    {"id": "zdh02", "priority": "MUST",     "tool": "github-js-sourcemap","target": "<target>", "status": "pending"},
    {"id": "zdh03", "priority": "MUST",     "tool": "ssrf-oob",           "target": "<target>", "status": "pending"},
    {"id": "zdh04", "priority": "MUST",     "tool": "jwt-saml-sso",       "target": "<target>", "status": "pending"},
    {"id": "zdh05", "priority": "MUST",     "tool": "chain-blueprints",   "target": "<target>", "status": "pending"},
    {"id": "zdh06", "priority": "SHOULD",   "tool": "business-logic",     "target": "<target>", "status": "pending"},
    {"id": "zdh07", "priority": "SHOULD",   "tool": "supply-chain",       "target": "<target>", "status": "pending"},
    {"id": "zdh08", "priority": "SHOULD",   "tool": "admin-infra",        "target": "<target>", "status": "pending"},
    {"id": "zdh09", "priority": "SHOULD",   "tool": "ssti-deser-xxe",     "target": "<target>", "status": "pending"},
    {"id": "zdh10", "priority": "SHOULD",   "tool": "cors-host",          "target": "<target>", "status": "pending"},
    {"id": "zdh11", "priority": "SHOULD",   "tool": "race-timing",        "target": "<target>", "status": "pending"},
    {"id": "zdh12", "priority": "SHOULD",   "tool": "cicd",               "target": "<target>", "status": "pending"},
    {"id": "zdh13", "priority": "SHOULD",   "tool": "graphql",            "target": "<target>", "status": "pending"},
    {"id": "zdh14", "priority": "IF_TIME",  "tool": "takeover-cloud",     "target": "<target>", "status": "pending"},
    {"id": "zdh15", "priority": "IF_TIME",  "tool": "mobile-apk",         "target": "<target>", "status": "pending"},
    {"id": "zdh16", "priority": "IF_TIME",  "tool": "client-proto",       "target": "<target>", "status": "pending"},
    {"id": "zdh17", "priority": "IF_TIME",  "tool": "file-crypto",        "target": "<target>", "status": "pending"},
    {"id": "zdh18", "priority": "IF_TIME",  "tool": "websocket-api",      "target": "<target>", "status": "pending"},
    {"id": "zdh19", "priority": "IF_TIME",  "tool": "xs-leaks",           "target": "<target>", "status": "pending"},
    {"id": "zdh20", "priority": "MUST",     "tool": "output",             "target": "<target>", "status": "pending"}
  ]
}
```

---

## Technique Loader

Load the relevant technique file from `~/.claude/skills/zerodayhunt/tech/` based on active manifest item:

| Manifest item | File | Phases covered |
|---|---|---|
| waf-header-mining | tech/waf-header-mining.md | Phase 2, 3, 20 |
| github-js-sourcemap | tech/github-js-sourcemap.md | Phase 4, 5, 18 |
| supply-chain | tech/supply-chain.md | Phase 6 |
| jwt-saml-sso | tech/jwt-saml-sso.md | Phase 7, 31 |
| ssrf-oob | tech/ssrf-oob.md | Phase 8, 32 |
| business-logic | tech/business-logic.md | Phase 9, 27 |
| race-timing | tech/race-timing.md | Phase 10, 21 |
| takeover-cloud | tech/takeover-cloud.md | Phase 11, 12 |
| mobile-apk | tech/mobile-apk.md | Phase 13 |
| cors-host | tech/cors-host.md | Phase 14 |
| ssti-deser-xxe | tech/ssti-deser-xxe.md | Phase 15 |
| cicd | tech/cicd.md | Phase 16 |
| graphql | tech/graphql.md | Phase 17 |
| admin-infra | tech/admin-infra.md | Phase 19, 28 |
| websocket-api | tech/websocket-api.md | Phase 22 |
| chain-blueprints | tech/chain-blueprints.md | Phase 23 |
| client-proto | tech/client-proto.md | Phase 24, 25 |
| file-crypto | tech/file-crypto.md | Phase 26, 29 |
| xs-leaks | tech/xs-leaks.md | Phase 30 |
| output | tech/output.md | Evidence Classification + Output + Phase-End |

---

## Hypothesis-Driven Prioritization

After Phase 0, reprioritize manifest based on intel:

| Condition | Move to MUST |
|---|---|
| `AWS_HINT=true` and any SSRF vector | ssrf-oob, chain-blueprints (Chain B/H) |
| `JWT_TOKENS` found | jwt-saml-sso |
| `TECH_STACK` contains Node.js | client-proto (prototype pollution) |
| `TECH_STACK` contains Java/Spring | ssti-deser-xxe |
| GraphQL endpoint discovered | graphql |
| GitHub org found in recon | github-js-sourcemap, supply-chain, cicd |
| E-commerce target | business-logic, race-timing |
| `SSRF_VECTORS` from exploit relay | ssrf-oob (escalate existing) |
| `CONFIRMED_VULNS` has any finding | chain-blueprints (always) |

Skip ATW-flagged techniques. Doom loop guard in output.md.

---

## Signal Reference

All signals emitted via `emit_signal` from `_shared/signals.sh`:

| Signal type | When | Confidence |
|---|---|---|
| `VULN_CONFIRMED` | Full chain proven with evidence | 0.93-0.97 |
| `SURFACE_FOUND` | New attack surface (takeover, supply chain) | 0.88-0.90 |
| `CRED_FOUND` | Credential discovered and verified | 0.92 |
| `POTENTIAL` | Probe positive but chain unconfirmed | 0.60-0.75 |
