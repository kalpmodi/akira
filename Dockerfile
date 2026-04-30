# ─────────────────────────────────────────────────────────────────────────────
# Akira - Autonomous Offensive Security Agent
# Full toolchain image: every tool referenced across all 68 technique files
# Base: kali-rolling (pre-packages most security tools via apt)
# ─────────────────────────────────────────────────────────────────────────────
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
ENV GOROOT=/usr/local/go
ENV GOPATH=/root/go
ENV PATH=$PATH:/usr/local/go/bin:/root/go/bin:/opt/tools/bin

# ── Base & build dependencies ────────────────────────────────────────────────
RUN apt-get update && apt-get install -y \
    curl wget git jq vim unzip zip p7zip-full \
    python3 python3-pip python3-dev python3-venv \
    ruby ruby-dev rubygems \
    default-jdk nodejs npm \
    build-essential gcc g++ make cmake nasm \
    libssl-dev libffi-dev libpcap-dev libkrb5-dev \
    zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

# ── Go 1.22 ──────────────────────────────────────────────────────────────────
RUN wget -q https://go.dev/dl/go1.22.4.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go1.22.4.linux-amd64.tar.gz \
    && rm go1.22.4.linux-amd64.tar.gz

# ── Kali apt security suite ───────────────────────────────────────────────────
RUN apt-get update && apt-get install -y \
    # network & scanning
    nmap masscan netcat-openbsd ncat socat \
    tcpdump tshark dnsutils whois \
    aircrack-ng \
    # web
    sqlmap nikto whatweb gobuster dirsearch wfuzz feroxbuster \
    # password
    hashcat john hydra crunch \
    # AD / Windows
    responder evil-winrm impacket-scripts \
    crackmapexec certipy-ad bloodhound-python kerbrute \
    # misc
    seclists wordlists \
    wabt \
    steghide \
    && rm -rf /var/lib/apt/lists/*

# ── Go-based tools ────────────────────────────────────────────────────────────
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest    && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest                && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest                  && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest           && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest              && \
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest             && \
    go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest              && \
    go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest && \
    go install github.com/projectdiscovery/interactsh/cmd/interactsh-server@latest && \
    go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest         && \
    go install github.com/projectdiscovery/cloudlist/cmd/cloudlist@latest        && \
    go install github.com/lc/gau/v2/cmd/gau@latest                               && \
    go install github.com/ffuf/ffuf/v2@latest                                     && \
    go install github.com/hahwul/dalfox/v2@latest                                 && \
    go install github.com/OJ/gobuster/v3@latest                                   && \
    go install github.com/d3mondev/puredns/v2@latest                              && \
    go install github.com/owasp-amass/amass/v4/...@master                         && \
    go install github.com/tomnomnom/waybackurls@latest                            && \
    go install github.com/tomnomnom/anew@latest                                   && \
    go install github.com/tomnomnom/httprobe@latest                               && \
    go install github.com/tomnomnom/assetfinder@latest                            && \
    go install github.com/tomnomnom/gf@latest                                     && \
    go install github.com/tomnomnom/qsreplace@latest                              && \
    go install github.com/tomnomnom/unfurl@latest                                 && \
    go install github.com/hakluke/hakrawler@latest                                && \
    go install github.com/jaeles-project/gospider@latest                          && \
    go install github.com/003random/getJS/v2@latest                               && \
    go install github.com/s0md3v/smap/cmd/smap@latest                             && \
    go install github.com/rverton/webanalyze/cmd/webanalyze@latest                && \
    go install github.com/xm1k3/cent@latest                                       && \
    go install github.com/dwisiswant0/cf-check@latest                             && \
    go install github.com/theblackturtle/puredns@latest 2>/dev/null || true

# ── Nuclei templates ──────────────────────────────────────────────────────────
RUN nuclei -update-templates 2>/dev/null || true

# ── Python pip tools ──────────────────────────────────────────────────────────
RUN pip3 install --no-cache-dir --break-system-packages \
    impacket \
    bloodhound \
    certipy-ad \
    pypykatz \
    roadtx \
    pacu \
    prowler \
    cloudsplaining \
    semgrep \
    arjun \
    waymore \
    coercer \
    dsinternals \
    ldapdomaindump \
    pwncat-cs \
    objection \
    frida-tools \
    crackmapexec \
    netexec \
    paramspider \
    apk-mitm \
    requests \
    boto3 \
    google-cloud-storage \
    azure-identity \
    azure-mgmt-compute

# ── Git-cloned Python tools ───────────────────────────────────────────────────
WORKDIR /opt

# LinkFinder - JS endpoint extractor
RUN git clone --depth 1 https://github.com/GerbenJavado/LinkFinder.git && \
    pip3 install --no-cache-dir --break-system-packages \
        -r /opt/LinkFinder/requirements.txt && \
    echo '#!/bin/bash\npython3 /opt/LinkFinder/linkfinder.py "$@"' > /usr/local/bin/linkfinder && \
    chmod +x /usr/local/bin/linkfinder

# SecretFinder - API key detector in JS
RUN git clone --depth 1 https://github.com/m4ll0k/SecretFinder.git && \
    pip3 install --no-cache-dir --break-system-packages \
        -r /opt/SecretFinder/requirements.txt && \
    echo '#!/bin/bash\npython3 /opt/SecretFinder/SecretFinder.py "$@"' > /usr/local/bin/secretfinder && \
    chmod +x /usr/local/bin/secretfinder

# cloud_enum - S3/GCS/Azure blob enumeration
RUN git clone --depth 1 https://github.com/initstring/cloud_enum.git && \
    pip3 install --no-cache-dir --break-system-packages \
        -r /opt/cloud_enum/requirements.txt && \
    echo '#!/bin/bash\npython3 /opt/cloud_enum/cloud_enum.py "$@"' > /usr/local/bin/cloud_enum && \
    chmod +x /usr/local/bin/cloud_enum

# enumerate-iam - AWS IAM permission brute-forcer
RUN git clone --depth 1 https://github.com/andresriancho/enumerate-iam.git && \
    pip3 install --no-cache-dir --break-system-packages \
        -r /opt/enumerate-iam/requirements.txt

# jwt_tool - JWT manipulation and testing
RUN git clone --depth 1 https://github.com/ticarpi/jwt_tool.git && \
    pip3 install --no-cache-dir --break-system-packages \
        -r /opt/jwt_tool/requirements.txt && \
    echo '#!/bin/bash\npython3 /opt/jwt_tool/jwt_tool.py "$@"' > /usr/local/bin/jwt_tool && \
    chmod +x /usr/local/bin/jwt_tool

# dnsReaper - subdomain takeover detection
RUN git clone --depth 1 https://github.com/punk-security/dnsReaper.git && \
    pip3 install --no-cache-dir --break-system-packages \
        -r /opt/dnsReaper/requirements.txt 2>/dev/null || true && \
    echo '#!/bin/bash\npython3 /opt/dnsReaper/main.py "$@"' > /usr/local/bin/dnsreaper && \
    chmod +x /usr/local/bin/dnsreaper

# PetitPotam - NTLM relay trigger
RUN git clone --depth 1 https://github.com/topotam/PetitPotam.git

# noPac - CVE-2021-42278/42287 sAMAccountName spoofing
RUN git clone --depth 1 https://github.com/Ridter/noPac.git && \
    pip3 install --no-cache-dir --break-system-packages \
        -r /opt/noPac/requirements.txt 2>/dev/null || true

# PKINITtools - Kerberos PKINIT / ADCS abuse
RUN git clone --depth 1 https://github.com/dirkjanm/PKINITtools.git && \
    pip3 install --no-cache-dir --break-system-packages \
        -r /opt/PKINITtools/requirements.txt 2>/dev/null || true

# rbcd-attack - Resource-based constrained delegation
RUN git clone --depth 1 https://github.com/tothi/rbcd-attack.git

# Coercer - Windows auth coercion (all MS-* protocols)
RUN git clone --depth 1 https://github.com/p0dalirius/Coercer.git && \
    pip3 install --no-cache-dir --break-system-packages \
        /opt/Coercer 2>/dev/null || true

# nginxpwner - Nginx alias traversal scanner
RUN git clone --depth 1 https://github.com/stark0de/nginxpwner.git && \
    pip3 install --no-cache-dir --break-system-packages \
        -r /opt/nginxpwner/requirements.txt 2>/dev/null || true && \
    echo '#!/bin/bash\npython3 /opt/nginxpwner/nginxpwner.py "$@"' > /usr/local/bin/nginxpwner && \
    chmod +x /usr/local/bin/nginxpwner

# v8_rand_buster - Math.random() V8 state recovery
RUN git clone --depth 1 https://github.com/d0nutptr/v8_rand_buster.git

# ecdsa-private-key-recovery - ECDSA nonce reuse attack
RUN git clone --depth 1 https://github.com/tintinweb/ecdsa-private-key-recovery.git && \
    pip3 install --no-cache-dir --break-system-packages \
        -r /opt/ecdsa-private-key-recovery/requirements.txt 2>/dev/null || true

# dnsgen - subdomain permutation generator
RUN pip3 install --no-cache-dir --break-system-packages dnsgen && \
    echo "dnsgen installed via pip"

# gotator - advanced subdomain permutation
RUN go install github.com/Josue87/gotator@latest

# subjack - subdomain takeover scanner
RUN go install github.com/haccer/subjack@latest

# s3scanner - S3 bucket access verifier
RUN go install github.com/sa7mon/s3scanner@latest

# singularity - DNS rebinding framework
RUN git clone --depth 1 https://github.com/nccgroup/singularity.git && \
    cd /opt/singularity/cmd/singularity-server && \
    go build -o /usr/local/bin/singularity-server . 2>/dev/null || true

# ── massdns - high-performance DNS resolver ───────────────────────────────────
RUN git clone --depth 1 https://github.com/blechschmidt/massdns.git /opt/massdns && \
    make -C /opt/massdns && cp /opt/massdns/bin/massdns /usr/local/bin/

# ── Binary downloads ──────────────────────────────────────────────────────────

# gitleaks
RUN GITLEAKS_VER=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest \
        | jq -r '.tag_name') && \
    wget -q "https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VER}/gitleaks_${GITLEAKS_VER#v}_linux_x64.tar.gz" \
        -O /tmp/gitleaks.tar.gz && \
    tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks && \
    rm /tmp/gitleaks.tar.gz

# trufflehog
RUN wget -q "https://github.com/trufflesecurity/trufflehog/releases/latest/download/trufflehog_linux_amd64.tar.gz" \
        -O /tmp/trufflehog.tar.gz && \
    tar -xzf /tmp/trufflehog.tar.gz -C /usr/local/bin trufflehog && \
    rm /tmp/trufflehog.tar.gz

# kerbrute
RUN KERBRUTE_VER=$(curl -s https://api.github.com/repos/ropnop/kerbrute/releases/latest \
        | jq -r '.tag_name') && \
    wget -q "https://github.com/ropnop/kerbrute/releases/download/${KERBRUTE_VER}/kerbrute_linux_amd64" \
        -O /usr/local/bin/kerbrute && chmod +x /usr/local/bin/kerbrute

# feroxbuster (latest binary)
RUN FEROX_VER=$(curl -s https://api.github.com/repos/epi052/feroxbuster/releases/latest \
        | jq -r '.tag_name') && \
    wget -q "https://github.com/epi052/feroxbuster/releases/download/${FEROX_VER}/x86_64-linux-feroxbuster.zip" \
        -O /tmp/ferox.zip && \
    unzip -q /tmp/ferox.zip -d /usr/local/bin && chmod +x /usr/local/bin/feroxbuster && \
    rm /tmp/ferox.zip

# ysoserial - Java deserialization payloads
RUN wget -q "https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar" \
        -O /usr/local/share/ysoserial.jar && \
    echo '#!/bin/bash\njava -jar /usr/local/share/ysoserial.jar "$@"' > /usr/local/bin/ysoserial && \
    chmod +x /usr/local/bin/ysoserial

# jadx - Android APK decompiler
RUN JADX_VER=$(curl -s https://api.github.com/repos/skylot/jadx/releases/latest \
        | jq -r '.tag_name') && \
    wget -q "https://github.com/skylot/jadx/releases/download/${JADX_VER}/jadx-${JADX_VER#v}.zip" \
        -O /tmp/jadx.zip && \
    unzip -q /tmp/jadx.zip -d /opt/jadx && \
    ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx && \
    ln -sf /opt/jadx/bin/jadx-gui /usr/local/bin/jadx-gui && \
    rm /tmp/jadx.zip

# apk-mitm - APK certificate pinning bypass
RUN npm install -g apk-mitm 2>/dev/null || true

# Sliver C2 server + client
RUN wget -q "https://github.com/BishopFox/sliver/releases/latest/download/sliver-server_linux" \
        -O /usr/local/bin/sliver-server && chmod +x /usr/local/bin/sliver-server && \
    wget -q "https://github.com/BishopFox/sliver/releases/latest/download/sliver-client_linux" \
        -O /usr/local/bin/sliver-client && chmod +x /usr/local/bin/sliver-client

# LinPEAS / WinPEAS
RUN mkdir -p /opt/peas && \
    wget -q "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh" \
        -O /opt/peas/linpeas.sh && chmod +x /opt/peas/linpeas.sh && \
    wget -q "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe" \
        -O /opt/peas/winPEASx64.exe && \
    ln -sf /opt/peas/linpeas.sh /usr/local/bin/linpeas

# ptunnel-ng - ICMP tunneling
RUN git clone --depth 1 https://github.com/utoni/ptunnel-ng.git /opt/ptunnel-ng && \
    cd /opt/ptunnel-ng && cmake . && make && \
    cp ptunnel-ng /usr/local/bin/ 2>/dev/null || true

# icmpsh - ICMP reverse shell
RUN git clone --depth 1 https://github.com/bdamele/icmpsh.git /opt/icmpsh && \
    gcc /opt/icmpsh/icmpsh.c -o /usr/local/bin/icmpsh 2>/dev/null || true

# dnscat2 - DNS tunneling C2
RUN gem install dnscat2 2>/dev/null || \
    git clone --depth 1 https://github.com/iagox86/dnscat2.git /opt/dnscat2

# Metasploit Framework
RUN curl -s https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb \
        > /tmp/msfinstall && chmod +x /tmp/msfinstall && /tmp/msfinstall 2>/dev/null || \
    apt-get update && apt-get install -y metasploit-framework 2>/dev/null && \
    rm -rf /var/lib/apt/lists/*

# Havoc C2 framework
RUN apt-get update && apt-get install -y nasm mingw-w64 2>/dev/null && \
    rm -rf /var/lib/apt/lists/* && \
    git clone --depth 1 https://github.com/HavocFramework/Havoc.git /opt/havoc 2>/dev/null || true

# ── Cloud CLIs ────────────────────────────────────────────────────────────────

# AWS CLI v2
RUN curl -s "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip && \
    unzip -q /tmp/awscliv2.zip -d /tmp && \
    /tmp/aws/install && \
    rm -rf /tmp/aws /tmp/awscliv2.zip

# Google Cloud CLI
RUN echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] \
        https://packages.cloud.google.com/apt cloud-sdk main" \
        > /etc/apt/sources.list.d/google-cloud-sdk.list && \
    curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg \
        | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg && \
    apt-get update && apt-get install -y google-cloud-cli && \
    rm -rf /var/lib/apt/lists/*

# Azure CLI
RUN curl -fsSL https://aka.ms/InstallAzureCLIDeb | bash 2>/dev/null || \
    pip3 install --no-cache-dir --break-system-packages azure-cli

# kubectl
RUN curl -sLO "https://dl.k8s.io/release/$(curl -sL https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" && \
    chmod +x kubectl && mv kubectl /usr/local/bin/

# AzureHound - Azure AD data collector
RUN AZHOUND_VER=$(curl -s https://api.github.com/repos/BloodHoundAD/AzureHound/releases/latest \
        | jq -r '.tag_name') && \
    wget -q "https://github.com/BloodHoundAD/AzureHound/releases/download/${AZHOUND_VER}/azurehound-linux-amd64.zip" \
        -O /tmp/azurehound.zip && \
    unzip -q /tmp/azurehound.zip -d /usr/local/bin && \
    chmod +x /usr/local/bin/azurehound-linux-amd64 && \
    ln -sf /usr/local/bin/azurehound-linux-amd64 /usr/local/bin/azurehound && \
    rm /tmp/azurehound.zip

# ── SecLists wordlists ────────────────────────────────────────────────────────
RUN git clone --depth 1 https://github.com/danielmiessler/SecLists.git /opt/SecLists

# ── Copy Akira skills into image ──────────────────────────────────────────────
WORKDIR /akira
COPY . .
RUN bash install.sh 2>/dev/null || true

# ── Tool inventory check ──────────────────────────────────────────────────────
RUN echo "\n=== Akira Toolchain Inventory ===" && \
    for t in subfinder httpx dnsx nuclei katana gau ffuf dalfox naabu asnmap \
              chaos interactsh-client interactsh-server gobuster puredns amass \
              waybackurls assetfinder gotator subjack s3scanner massdns dnsgen \
              nmap masscan sqlmap nikto whatweb feroxbuster wfuzz dalfox \
              hashcat john hydra \
              crackmapexec evil-winrm responder kerbrute certipy \
              gitleaks trufflehog \
              linkfinder secretfinder cloud_enum jwt_tool nginxpwner dnsreaper \
              ysoserial jadx \
              sliver-server sliver-client \
              linpeas \
              aws gcloud az kubectl azurehound \
              jq git curl wget python3 ruby java node; do \
        command -v "$t" &>/dev/null && echo "  [✓] $t" || echo "  [✗] $t"; \
    done && echo ""

WORKDIR /workspace

CMD ["/bin/bash"]
