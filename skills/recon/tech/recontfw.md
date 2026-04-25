# Recon Step 22: reconFTW - Orchestration Framework

When you want everything automated in one pipeline, reconFTW orchestrates 50+ tools with dependency management, deduplication, and prioritized output.

```bash
TARGET="target.com"
RESULTS=~/pentest-toolkit/results/$TARGET

# reconFTW full mode - runs everything: passive, active, JS, vulns, screenshots
# https://github.com/six2dez/reconftw
reconftw.sh -d $TARGET -a \
  --output $RESULTS/recon/reconftw/ \
  2>/dev/null

# Subdomain-only (when you have tight time budget):
reconftw.sh -d $TARGET -s --output $RESULTS/recon/reconftw/

# Web only (assumes subdomains already known):
reconftw.sh -d $TARGET -w --output $RESULTS/recon/reconftw/

# Passive only (no active requests to target - useful for strict scoping):
reconftw.sh -d $TARGET -p --output $RESULTS/recon/reconftw/
```

## reconFTW Built-in Toolchain

reconFTW includes and manages:
- **Subdomain enum:** subfinder, amass, github-subdomains, crt.sh, chaos
- **Resolution:** shuffledns, massdns
- **Live probe:** httpx with screenshots
- **URL discovery:** gau, waybackurls, katana
- **JS analysis:** subjs, mantra, linkfinder
- **Vuln scan:** nuclei (all templates), dalfox (XSS), sqlmap
- **Source map extraction:** sourcemapper
- **Takeover:** nuclei takeover templates
- **Secrets:** gitleaks, trufflehog
- **Distributed mode:** sends tasks to remote workers (AX Framework)

```bash
# Merge reconFTW results back into main recon output
if [ -d "$RESULTS/recon/reconftw" ]; then
  # Subdomains
  cat $RESULTS/recon/reconftw/*/subdomains*.txt 2>/dev/null | sort -u >> $RESULTS/recon/all-subdomains.txt
  sort -u $RESULTS/recon/all-subdomains.txt -o $RESULTS/recon/all-subdomains.txt

  # URLs
  cat $RESULTS/recon/reconftw/*/url*.txt 2>/dev/null | sort -u >> $RESULTS/recon/urls/all-urls.txt
  sort -u $RESULTS/recon/urls/all-urls.txt -o $RESULTS/recon/urls/all-urls.txt

  # Vulnerabilities found
  cat $RESULTS/recon/reconftw/*/vulns*.txt 2>/dev/null | head -20
fi

echo "[*] reconFTW complete - check $RESULTS/recon/reconftw/"
```

## Manual Distributed Recon (AWS / VPS)

For large programs where IP rate limiting is a concern:

```bash
# Split subdomain list across multiple VPS nodes:
# Split resolvers per node, run puredns resolve in parallel
split -n l/4 $RESULTS/recon/all-subdomains.txt /tmp/chunk_

# Each node:
# puredns resolve /tmp/chunk_aa --resolvers node1-resolvers.txt --write /tmp/resolved_1.txt
# puredns resolve /tmp/chunk_ab --resolvers node2-resolvers.txt --write /tmp/resolved_2.txt

# Collect results and merge:
# cat /tmp/resolved_*.txt | sort -u >> $RESULTS/recon/resolved.txt
```
