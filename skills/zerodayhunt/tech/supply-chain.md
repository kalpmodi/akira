# ZDH Phase 6: Dependency Confusion Attack Surface

**Checklist (ALL required before reporting):**
- [ ] Namespace unclaimed on public registry (prove with API call)
- [ ] Target uses this namespace internally (stack trace, pom.xml, import statement)
- [ ] Private registry DNS confirmed (nexus.*, artifactory.*)

```bash
# npm scope check
curl https://registry.npmjs.org/-/org/<orgname>/package  # 404 = unclaimed

# Maven Central
curl "https://search.maven.org/solrsearch/select?q=g:<groupId>&rows=5&wt=json"
# numFound:0 = unclaimed

# Find internal groupIds from Spring Boot error stack traces:
# "com.example.internal.api" in stack trace = internal Java package

# Confirm private registry:
dig nexus.<target-corp>.com    # private IP = Nexus confirmed
dig artifactory.<target-corp>.com

# PyPI for Python targets
curl https://pypi.org/pypi/<package-name>/json  # 404 = unclaimed
```

**NEVER publish. Report as:** "PoC available as DNS-only proof upon written authorization."

## Where to Find Internal Package Names

```bash
# 1. JavaScript source maps (Phase 18): extract from .map files
# 2. Webpack chunks (Phase 5): re.findall(r'node_modules/([^/\'"]+)', js_source)
# 3. Java stack traces in error responses:
#    "com.example.internal.*" = internal Java group ID
# 4. Maven/Gradle config in GitHub repos (Phase 4):
#    - pom.xml: <groupId>com.corp.internal</groupId>
#    - build.gradle: implementation 'com.corp.internal:service:1.0'
# 5. Python requirements.txt / setup.py in repos
# 6. Wayback CDX API: fetch historical package.json files

# Cross-reference discovered names with each registry:
for PKG in $(cat discovered_packages.txt); do
  npm_status=$(curl -s -o /dev/null -w "%{http_code}" "https://registry.npmjs.org/$PKG")
  maven_count=$(curl -s "https://search.maven.org/solrsearch/select?q=g:$PKG&rows=1&wt=json" | jq -r '.response.numFound')
  pypi_status=$(curl -s -o /dev/null -w "%{http_code}" "https://pypi.org/pypi/$PKG/json")
  echo "$PKG | npm:$npm_status | maven:$maven_count | pypi:$pypi_status"
done
```

## CI/CD Supply Chain (GitHub Actions specific)

```bash
# Check for unclaimed reusable workflow namespaces:
# If workflow uses: uses: <org>/<repo>/.github/workflows/build.yml@main
# And <org>/<repo> doesn't exist on GitHub -> register it -> all workflows using it run your code

# Check .github/workflows/ for external action dependencies:
grep -r "uses:" .github/workflows/ | grep -v "actions/" | awk '{print $2}' | sort -u
# For each: check if GitHub org/repo exists. If not -> register.

# Internal GitHub App supply chain:
# If app uses: github.com/apps/<name> for CI/CD integration
# Verify app still exists at https://github.com/apps/<name>
```

**Signal:** `emit_signal SURFACE_FOUND "Dependency confusion: <package> unclaimed on <registry>" "main/zerodayhunt" 0.90`
