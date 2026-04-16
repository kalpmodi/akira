#!/bin/bash
# Akira Demo Simulator
# Shows realistic Akira engagement output for demo recording
# Usage: bash simulate.sh | cat
# For GIF: use with vhs (demo.tape) or asciinema

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

TARGET="demo-target.com"

print_slow() {
    echo -e "$1"
    sleep 0.4
}

clear
echo ""
echo -e "${BOLD}${CYAN} █████╗ ██╗  ██╗██╗██████╗  █████╗ ${RESET}"
echo -e "${BOLD}${CYAN}██╔══██╗██║ ██╔╝██║██╔══██╗██╔══██╗${RESET}"
echo -e "${BOLD}${CYAN}███████║█████╔╝ ██║██████╔╝███████║${RESET}"
echo -e "${BOLD}${CYAN}██╔══██║██╔═██╗ ██║██╔══██╗██╔══██║${RESET}"
echo -e "${BOLD}${CYAN}██║  ██║██║  ██╗██║██║  ██║██║  ██║${RESET}"
echo -e "${BOLD}${CYAN}╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝${RESET}"
echo ""
echo -e "${BOLD}  The AI Pentest Co-Pilot That Actually Finds Bugs${RESET}"
echo ""
sleep 1

echo -e "${BOLD}> /plan-engagement ${TARGET}${RESET}"
sleep 0.5
print_slow "  Initializing engagement: ${TARGET}"
print_slow "  Writing session.json..."
print_slow "  PTT initialized: 9 attack nodes"
echo -e "  ${GREEN}[ok]${RESET} Plan saved → ~/pentest-toolkit/results/${TARGET}/plan.md"
echo -e "  ${GREEN}[ok]${RESET} Session tracking live. Run /recon to start."
echo ""
sleep 0.8

echo -e "${BOLD}> /recon ${TARGET}${RESET}"
sleep 0.5
print_slow "  Running subfinder... found 23 subdomains"
print_slow "  Running httpx... 14 live hosts"
print_slow "  Running nmap on live hosts..."
print_slow "  Running katana for URL collection... 1,847 URLs"
echo ""
echo -e "  ${GREEN}[CONFIRMED]${RESET} api.${TARGET}        — live, ports: 80, 443, 8443"
echo -e "  ${GREEN}[CONFIRMED]${RESET} admin.${TARGET}      — live, ports: 443 (nginx/1.18)"
echo -e "  ${GREEN}[CONFIRMED]${RESET} staging.${TARGET}    — live, ports: 443, 9200 (Elasticsearch!)"
echo -e "  ${YELLOW}[POTENTIAL]${RESET} internal.${TARGET}  — resolved, not probed (out-of-scope)"
echo ""
echo -e "  ${BOLD}Tech stack:${RESET} Node.js 18, nginx/1.18, AWS CloudFront, PostgreSQL"
echo -e "  ${GREEN}[ok]${RESET} interesting_recon.md written. Run /secrets to continue."
echo ""
sleep 0.8

echo -e "${BOLD}> /secrets ${TARGET}${RESET}"
sleep 0.5
print_slow "  Scanning 1,847 URLs for secrets..."
print_slow "  Running trufflehog on JS bundles..."
print_slow "  Checking GitHub for leaked credentials..."
print_slow "  Probing API spec endpoints..."
echo ""
echo -e "  ${RED}[CONFIRMED]${RESET} AWS_ACCESS_KEY_ID in /static/js/main.chunk.js"
echo -e "             AKIA4EXAMPLE... (verified via sts:GetCallerIdentity)"
echo -e "  ${RED}[CONFIRMED]${RESET} API spec found at /api/swagger.json"
echo -e "             47 undocumented endpoints extracted"
echo -e "  ${YELLOW}[POTENTIAL]${RESET} JWT secret candidate in config.js (base64)"
echo ""
echo -e "  ${GREEN}[ok]${RESET} interesting_secrets.md written. Run /exploit to continue."
echo ""
sleep 0.8

echo -e "${BOLD}> /cloud-audit ${TARGET}${RESET}"
sleep 0.5
print_slow "  Verifying AWS credentials from secrets phase..."
print_slow "  aws sts get-caller-identity..."
echo ""
echo -e "  ${RED}[CRITICAL]${RESET} Credentials confirmed: arn:aws:iam::123456789:user/ci-deploy"
print_slow "  Enumerating accessible services..."
echo -e "  ${RED}[CRITICAL]${RESET} S3: 4 buckets accessible"
echo -e "             prod-db-backups/ → MySQL dump with 2.1M user records"
echo -e "             prod-env-files/  → .env files with DB passwords"
echo -e "  ${RED}[CRITICAL]${RESET} Secrets Manager: 12 secrets accessible"
echo -e "             /prod/database/master_password → exposed"
echo ""
echo -e "  ${BOLD}${RED}Chain complete: JS bundle → AWS key → S3 → production data${RESET}"
echo -e "  ${GREEN}[ok]${RESET} interesting_cloud-audit.md written."
echo ""
sleep 0.8

echo -e "${BOLD}> /triage ${TARGET}${RESET}"
sleep 0.5
print_slow "  Reading all phase outputs..."
print_slow "  Running FP verification gate..."
print_slow "  Calculating confidence scores..."
echo ""
echo -e "  ${BOLD}CRITICAL (Confidence: 97)${RESET}"
echo -e "  ├── AWS key in JS bundle → S3 prod-db-backups access"
echo -e "  │   Evidence: aws s3 ls confirmed + 2.1M records accessible"
echo -e "  └── Elasticsearch on staging:9200 — unauthenticated access"
echo ""
echo -e "  ${BOLD}HIGH (Confidence: 85)${RESET}"
echo -e "  └── 47 undocumented API endpoints via leaked swagger.json"
echo ""
echo -e "  ${GREEN}[ok]${RESET} triage.md written. Run /report to generate deliverable."
echo ""
sleep 0.8

echo -e "${BOLD}> /report ${TARGET}${RESET}"
sleep 0.3
print_slow "  Generating pentest report..."
echo -e "  ${GREEN}[ok]${RESET} report-2026-04-16.md written"
echo -e "  ${GREEN}[ok]${RESET} bugbounty-2026-04-16.md written (HackerOne format)"
echo ""
echo -e "  ${BOLD}Summary: 2 Critical | 1 High | 0 Medium | 0 False Positives${RESET}"
echo ""
echo -e "${CYAN}  github.com/Kalp1774/akira${RESET}"
echo ""
