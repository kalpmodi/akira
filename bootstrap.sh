#!/bin/bash
# Akira Bootstrap - installs all required pentest tools
# Usage: bash bootstrap.sh
# Supports: macOS (brew), Debian/Ubuntu (apt), Kali

set -e

VERSIONS_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/toolchain/versions.env"
[ -f "$VERSIONS_FILE" ] && source "$VERSIONS_FILE"

echo ""
echo "  Akira Bootstrap - Installing Toolchain"
echo "  ======================================="
echo ""

# Detect package manager
if command -v brew &>/dev/null; then
    PM="brew"
    echo "  Detected: macOS (Homebrew)"
elif command -v apt-get &>/dev/null; then
    PM="apt"
    echo "  Detected: Debian/Ubuntu/Kali (apt)"
elif command -v dnf &>/dev/null; then
    PM="dnf"
    echo "  Detected: Fedora/RHEL (dnf)"
else
    PM="unknown"
    echo "  Warning: Unknown package manager. Installing Go tools only."
fi

echo ""

# Check Go
if ! command -v go &>/dev/null; then
    echo "  Go not found. Install Go first: https://go.dev/dl/"
    echo "  Then re-run bootstrap.sh"
    exit 1
fi
echo "  Go: $(go version | awk '{print $3}')"

# Go-based tools (ProjectDiscovery + others)
declare -A go_tools=(
    ["subfinder"]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VERSION:-v2.6.8}"
    ["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION:-v1.6.8}"
    ["dnsx"]="github.com/projectdiscovery/dnsx/cmd/dnsx@${DNSX_VERSION:-v1.2.1}"
    ["nuclei"]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION:-v3.3.2}"
    ["katana"]="github.com/projectdiscovery/katana/cmd/katana@${KATANA_VERSION:-v1.1.1}"
    ["gau"]="github.com/lc/gau/v2/cmd/gau@${GAU_VERSION:-v2.2.4}"
    ["ffuf"]="github.com/ffuf/ffuf/v2@${FFUF_VERSION:-v2.1.0}"
    ["dalfox"]="github.com/hahwul/dalfox/v2@${DALFOX_VERSION:-v2.12.0}"
    ["feroxbuster"]=""
)

echo ""
echo "  Installing Go-based tools..."
for tool in subfinder httpx dnsx nuclei katana gau ffuf dalfox; do
    if command -v "$tool" &>/dev/null; then
        echo "  [already installed] $tool"
    else
        echo "  Installing $tool..."
        go install "${go_tools[$tool]}" 2>/dev/null && echo "  [ok] $tool" || echo "  [failed] $tool"
    fi
done

# Python tools
echo ""
echo "  Installing Python tools..."
PYTHON=$(command -v python3 || command -v python)
PIP=$(command -v pip3 || command -v pip)

if [ -n "$PIP" ]; then
    for tool in trufflehog gitleaks; do
        if command -v "$tool" &>/dev/null; then
            echo "  [already installed] $tool"
        else
            echo "  Installing $tool..."
            $PIP install $tool 2>/dev/null && echo "  [ok] $tool" || echo "  [failed] $tool (try: pip install $tool)"
        fi
    done
fi

# System tools via package manager
echo ""
echo "  Installing system tools..."
system_tools=("nmap" "sqlmap" "feroxbuster")

for tool in "${system_tools[@]}"; do
    if command -v "$tool" &>/dev/null; then
        echo "  [already installed] $tool"
    elif [ "$PM" = "brew" ]; then
        echo "  Installing $tool via brew..."
        brew install "$tool" 2>/dev/null && echo "  [ok] $tool" || echo "  [failed] $tool"
    elif [ "$PM" = "apt" ]; then
        echo "  Installing $tool via apt..."
        sudo apt-get install -y "$tool" 2>/dev/null && echo "  [ok] $tool" || echo "  [failed] $tool"
    fi
done

# Nuclei templates update
if command -v nuclei &>/dev/null; then
    echo ""
    echo "  Updating nuclei templates..."
    nuclei -update-templates 2>/dev/null && echo "  [ok] nuclei templates" || true
fi

echo ""
echo "  Bootstrap complete!"
echo ""
echo "  Tool status:"
for tool in subfinder httpx dnsx nuclei katana ffuf dalfox feroxbuster nmap sqlmap trufflehog; do
    if command -v "$tool" &>/dev/null; then
        echo "    [x] $tool"
    else
        echo "    [ ] $tool (not installed)"
    fi
done
echo ""
echo "  Version source: toolchain/versions.env"
echo "  Start your first engagement: /plan-engagement <target>"
echo ""
