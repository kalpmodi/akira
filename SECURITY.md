# Security Policy

## Reporting a Bug in Akira

Found a bug, false positive pattern, or hallucination risk in Akira's skills?
Found a technique that's outdated, wrong, or dangerous?

**Open a GitHub Issue** - label it `security-bug` or `skill-bug`.

We treat skill accuracy bugs the same as code bugs. If Akira tells you something wrong during a live engagement, that matters.

---

## Reporting a Finding Made WITH Akira

Found a real vulnerability using Akira? We want to know (with your permission).

**What to do:**
1. Report the vulnerability to the target first (responsible disclosure)
2. After it's fixed or publicly disclosed, open a PR to [FINDINGS.md](FINDINGS.md)
3. We'll add it to the live findings table with attribution

You control how much detail goes in. Anonymous is fine. Program name optional.

---

## Suggesting New Techniques

Security is moving fast. If you know a technique that should be in Akira:

- Open an issue with label `technique-request`
- Describe: what attack vector, what tool, what evidence it produces
- Bonus: link to a public writeup or CVE

Good technique suggestions get fast-tracked into the next monthly release.

---

## Suggesting New Skills

Want a full new skill module (e.g., `graphql`, `mobile`, `deserialization`)?

- Open an issue with label `new-skill`
- Describe the attack surface, key techniques, and tools needed
- If you want to write it yourself, open a PR - attribution in CHANGELOG

The roadmap in README already lists planned skills. If yours is on the list, +1 the issue to help prioritize.

---

## Open to Contributions

Akira is fully open:
- Bug fixes - always welcome
- Technique improvements - always welcome
- New skills - welcome (see roadmap for planned modules)
- FINDINGS.md entries - always welcome

No CLA. No corporate BS. Just open a PR.

---

## Contact

GitHub Issues is the primary channel.
For sensitive disclosures about Akira itself (not findings made with it), use GitHub's private vulnerability reporting feature on this repo.
