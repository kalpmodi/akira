# Basilisk v1.1.0 Milestone Checklist

Use this file as the implementation board for Basilisk completion.

## Milestone Scope

- Thin-router + technique-library architecture hardening
- Unified Phase 0 behavior across applicable skills
- Race-proof signal handling
- `/redteam` integration hardening

## Done Criteria

- [ ] Core pipeline skills use shared intake and completion gates consistently
- [ ] Technique loading is explicit and traceable from router manifests
- [ ] Signal writes are append-only and avoid race-prone overwrite patterns
- [ ] `/redteam` phase output relays cleanly into `/triage` and `/report`
- [ ] At least one end-to-end dry run documented with generated artifacts
- [ ] `README.md` + `CHANGELOG.md` updated when milestone closes

## Tracking Notes

- Owner: Maintainer + contributors
- Validation gate: `.github/workflows/validate-skills.yml`
- Dependency updates: controlled through `toolchain/versions.env`
