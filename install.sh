#!/bin/bash

# Update package lists
apt-get update -y &>/dev/null

# Install system tools
apt-get install -y findomain massdns dnsrecon curl jq &>/dev/null
snap install shodan &>/dev/null

# Install Go tools
export PATH=$HOME/go/bin:$PATH

go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest &>/dev/null
go install github.com/OWASP/Amass/v3/...@master &>/dev/null
go install github.com/tomnomnom/assetfinder@latest &>/dev/null
go install github.com/tomnomnom/httprobe@latest &>/dev/null
go install github.com/lc/gau/v2/cmd/gau@latest &>/dev/null
go install github.com/tomnomnom/hakrawler@latest &>/dev/null
go install github.com/ffuf/ffuf@latest &>/dev/null
go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest &>/dev/null
go install github.com/projectdiscovery/httpx/cmd/httpx@latest &>/dev/null
go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest &>/dev/null

# Install Python tools
pip install git+https://github.com/devploit/subenum.git &>/dev/null
pip install git+https://github.com/devploit/knock.git &>/dev/null
pip install git+https://github.com/maurosoria/dirsearch.git &>/dev/null
pip install git+https://github.com/aboul3la/Sublist3r.git &>/dev/null
pip install git+https://github.com/devanshbatham/ParamSpider.git &>/dev/null
pip install git+https://github.com/s0md3v/Arjun.git &>/dev/null
pip install git+https://github.com/devploit/theHarvester.git &>/dev/null

# Install additional tools
apt-get install -y gobuster &>/dev/null

echo "[+] Installation of all tools is complete."
