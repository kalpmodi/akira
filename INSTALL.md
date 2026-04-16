# Akira - Installation Guide

## Quick Install (30 seconds)

```bash
git clone https://github.com/Kalp1774/akira
cd akira && bash install.sh
```

That installs all 12 skills into `~/.claude/skills/`. Open Claude Code and you're ready.

---

## Full Install (with tools)

```bash
git clone https://github.com/Kalp1774/akira
cd akira
bash install.sh      # install skills
bash bootstrap.sh    # install nuclei, dalfox, subfinder, httpx, sqlmap, etc.
```

---

## Platform-Specific Instructions

### Claude Code (Primary)

`install.sh` copies skills to `~/.claude/skills/`. Skills activate automatically.

```
/plan-engagement target.com   <- start here
/recon target.com
/secrets target.com
/exploit target.com
/triage target.com
/report target.com
```

### Gemini CLI

Copy the adapter to your Gemini skills path:

```bash
cp platform-adapters/GEMINI.md ~/.gemini/skills/akira.md
```

Or add the content to your existing `GEMINI.md`.

### Cursor

```bash
cp platform-adapters/.cursor/rules/akira.mdc ~/.cursor/rules/akira.mdc
```

Skills activate when you mention pentesting or security testing in your prompt.

### Codex / OpenAI Agents

See `platform-adapters/.codex/INSTALL.md`.

### Any AI Agent (Generic)

Reference `AGENTS.md` in your project root or agent configuration.

---

## Tools Installed by bootstrap.sh

| Tool | Purpose |
|---|---|
| subfinder | Subdomain enumeration |
| httpx | HTTP probing, live host detection |
| dnsx | DNS resolution at scale |
| nuclei | Vulnerability scanning (10k+ templates) |
| katana | JavaScript crawling, URL discovery |
| gau | Passive URL collection (Wayback, Common Crawl) |
| ffuf | Directory/parameter fuzzing |
| dalfox | XSS scanning and exploitation |
| feroxbuster | Directory fuzzing (Rust, fast) |
| nmap | Port scanning |
| sqlmap | SQL injection automation |
| trufflehog | Secrets scanning (git, JS, APIs) |

---

## Manual Tool Install (if bootstrap.sh fails)

```bash
# Go tools (requires Go 1.21+)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/hahwul/dalfox/v2@latest

# macOS
brew install nmap sqlmap feroxbuster

# Kali / Ubuntu
sudo apt-get install -y nmap sqlmap feroxbuster

# Python
pip install trufflehog
```

---

## Verify Installation

```
/plan-engagement example.com
```

Expected output: engagement plan created at `~/pentest-toolkit/results/example.com/plan.md`

If you see this, Akira is installed and ready.

---

## Update

```bash
cd akira
git pull
bash install.sh
```

Skills are overwritten with the latest version.
