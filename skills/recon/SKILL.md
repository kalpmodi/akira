---
name: recon
description: Use when running reconnaissance on a pentest target, starting phase 1 of an engagement, gathering subdomains, DNS resolution, live hosts, port scan results, URL intelligence, JavaScript endpoints, GitHub secrets, cloud buckets, subdomain takeovers, or attack surface mapping. Also use when the user says "run recon", "start recon", "phase 1", "enumerate subdomains", "find attack surface", or "map the target".
---

# Recon Phase - Router

Reconnaissance is the most important phase - the attack surface you find here directly determines what you can exploited. This router loads only the technique files your manifest requires.

**Technique library:** `~/.claude/skills/recon/tech/`

---

## Phase 0: Smart Intake

```bash
source ~/.claude/skills/_shared/phase0.sh
source ~/.claude/skills/_shared/signals.sh

p0_init_vars "$1"
p0_state_gate "HARVEST" || exit 0
p0_read_memory
# Recon is first phase - no intel relay from prior phases
```

**State gate:**
- `WIDE` - run full pipeline (all MUST + SHOULD items)
- `DEEP` - targeted only: r01, r02, r03, r04, r05 against active hypothesis surface; mark r06-r09 skipped
- `WRAP` - drain queued manifest items only; no new discovery
- `HARVEST` - exit immediately

---

## Execution Manifest

After Phase 0, build manifest based on STATE and hypothesis content:

```bash
jq '.scalpel.active_manifest = {
  "phase": "recon",
  "items": [
    {"id":"r01","tech":"asn-subdomain.md","desc":"ASN + passive subdomain + CT + brute","priority":"MUST","status":"pending"},
    {"id":"r02","tech":"live-hosts.md","desc":"httpx live probe + favicon + port scan","priority":"MUST","status":"pending"},
    {"id":"r03","tech":"urls.md","desc":"URL archive mining + JS analysis","priority":"MUST","status":"pending"},
    {"id":"r04","tech":"github.md","desc":"GitHub/GitLab dorking + TruffleHog","priority":"SHOULD","status":"pending"},
    {"id":"r05","tech":"cloud-buckets.md","desc":"S3/GCS/Azure/Firebase bucket discovery","priority":"SHOULD","status":"pending"},
    {"id":"r06","tech":"takeover.md","desc":"subdomain takeover detection","priority":"SHOULD","status":"pending"},
    {"id":"r07","tech":"osint.md","desc":"Google dorking + Shodan/Censys tech intel","priority":"SHOULD","status":"pending"},
    {"id":"r08","tech":"dns-advanced.md","desc":"AXFR zone transfer + NSEC walk + passive DNS","priority":"SHOULD","status":"pending"},
    {"id":"r09","tech":"scanners.md","desc":"FOFA/Netlas/LeakIX/CriminalIP queries","priority":"IF_TIME","status":"pending"},
    {"id":"r10","tech":"tls.md","desc":"JARM/JA4+ TLS fingerprinting","priority":"IF_TIME","status":"pending"},
    {"id":"r11","tech":"supply-chain.md","desc":"dependency confusion recon","priority":"IF_TIME","status":"pending"},
    {"id":"r12","tech":"wayback.md","desc":"Wayback CDX advanced mining","priority":"SHOULD","status":"pending"},
    {"id":"r13","tech":"recontfw.md","desc":"reconFTW orchestration pipeline","priority":"IF_TIME","status":"pending"},
    {"id":"r14","tech":"output.md","desc":"write interesting_recon.md + phase-end + intel relay","priority":"MUST","status":"pending"}
  ]
}' $SESSION > /tmp/s.json && mv /tmp/s.json $SESSION
```

---

## Technique Loader Table

Load technique files based on manifest and hypothesis content. Read ONLY what the manifest requires.

| Manifest ID | Technique file | Load when |
|---|---|---|
| r01 | `asn-subdomain.md` | Always (MUST) |
| r02 | `live-hosts.md` | Always (MUST) |
| r03 | `urls.md` | Always (MUST) |
| r04 | `github.md` | SHOULD + GitHub org found OR secrets hypothesis |
| r05 | `cloud-buckets.md` | SHOULD + cloud tech detected OR `cloud_hints.aws=true` |
| r06 | `takeover.md` | SHOULD + CNAMEs to third-party services found |
| r07 | `osint.md` | SHOULD + STATE=WIDE |
| r08 | `dns-advanced.md` | SHOULD + DNSSEC detected OR nameservers look outdated |
| r09 | `scanners.md` | IF_TIME + STATE=WIDE |
| r10 | `tls.md` | IF_TIME + CDN/WAF detected (need origin bypass) |
| r11 | `supply-chain.md` | IF_TIME + JS-heavy frontend OR dev hypothesis |
| r12 | `wayback.md` | SHOULD + large program OR old target domain |
| r13 | `recontfw.md` | IF_TIME + want full automation |
| r14 | `output.md` | Always (MUST - phase-end) |

### Hypothesis-driven reprioritization

| Hypothesis mentions | Reprioritize |
|---|---|
| AWS / GCP / Azure / cloud | r05 -> MUST first, r07 add cloud queries |
| JWT / OAuth / SSO | r03 (JS analysis) -> MUST first, r04 (GitHub) -> MUST |
| Supply chain / dependency | r11 -> MUST |
| SSRF / internal IP | r02 (port scan) -> MUST, r09 (scanners) -> SHOULD |
| Subdomain takeover | r06 -> MUST first |
| No specific hypothesis | Run r01-r14 in order |

---

## Signal Emission Reference

| Discovery | Signal type | Emit when |
|---|---|---|
| New subdomains (batch) | `SURFACE_FOUND` | After merge (r01) |
| Live host found | `SURFACE_FOUND` | Each host (r02) |
| Tech detected | `TECH_DETECTED` | Each framework/cloud (r02) |
| WAF fingerprinted | `WAF_CONFIRMED` | httpx WAF header (r02) |
| Unusual open port | `SURFACE_FOUND` | DB/internal exposed (r02) |
| Verified GitHub secret | `CRED_FOUND` | TruffleHog verified (r04) |
| Open cloud bucket | `SURFACE_FOUND` | Each accessible bucket (r05) |
| AXFR success | `SURFACE_FOUND` | Zone dump (r08) - CRITICAL, emit immediately |
| Subdomain takeover | `VULN_CONFIRMED` | Confirmed fingerprint (r06) |
| Unclaimed npm/pypi | `SURFACE_FOUND` | Each unclaimed package (r11) |

After every `TECH_DETECTED` signal, check correlation rules in plan-engagement Step 6.

---

## Completion Gate + Phase-End

After all MUST manifest items complete, run `p0_completion_gate || exit 1` then read `output.md` for intel relay instructions.

See `output.md` for the full Phase-End protocol: interesting_recon.md generation, session.json write-back, hypothesis calibration, fork candidates, completion gate, and intel relay write.
