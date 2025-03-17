#!/bin/bash

install_dependencies() {
    print_colored "Checking and installing required dependencies..." "$CYAN"

    # Check and install Python3
    if ! command -v python3 &>/dev/null; then
        print_colored "  [-] Python3 not found, installing..." "$YELLOW"
        sudo apt update && sudo apt install -y python3 || print_colored "  [!] Failed to install Python3" "$RED"
    else
        print_colored "  [+] Python3 is already installed" "$GREEN"
    fi

    # Check and install Pip3
    if ! command -v pip3 &>/dev/null; then
        print_colored "  [-] Pip3 not found, installing..." "$YELLOW"
        sudo apt install -y python3-pip || print_colored "  [!] Failed to install Pip3" "$RED"
    else
        print_colored "  [+] Pip3 is already installed" "$GREEN"
    fi

    # Check and install Go
    if ! command -v go &>/dev/null; then
        print_colored "  [-] Go not found, installing..." "$YELLOW"
        sudo apt install -y golang-go || print_colored "  [!] Failed to install Go" "$RED"
    else
        print_colored "  [+] Go is already installed" "$GREEN"
    fi

    # Install required apt packages
    local apt_packages=(git curl wget make gcc)
    for pkg in "${apt_packages[@]}"; do
        if ! dpkg -s "$pkg" &>/dev/null; then
            print_colored "  [-] $pkg not found, installing..." "$YELLOW"
            sudo apt install -y "$pkg" || print_colored "  [!] Failed to install $pkg" "$RED"
        else
            print_colored "  [+] $pkg is already installed" "$GREEN"
        fi
    done
}

install_tools() {
    print_colored "Checking and installing required security tools..." "$CYAN"
    
    local tools=(
        subfinder amass findomain assetfinder sublist3r subenum shodan gobuster 
        knockpy frogy alterx massdns shuffledns dnscan.py paramspider arjun katana 
        gospider gau waybackurls hakrawler ffuf
    )

    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            print_colored "  [-] $tool not found, installing..." "$YELLOW"
            case "$tool" in
                subfinder|amass|findomain|assetfinder|sublist3r|subenum|shodan|gobuster|katana|hakrawler)
                    go install github.com/projectdiscovery/$tool/v2/cmd/$tool@latest || print_colored "  [!] Failed to install $tool" "$RED"
                    ;;
                knockpy|frogy|alterx|dnscan.py|paramspider|arjun|gospider)
                    pip3 install "$tool" || print_colored "  [!] Failed to install $tool" "$RED"
                    ;;
                massdns)
                    git clone https://github.com/blechschmidt/massdns.git && cd massdns && make && sudo cp bin/massdns /usr/local/bin/ || print_colored "  [!] Failed to install massdns" "$RED"
                    ;;
                *)
                    sudo apt install -y "$tool" || print_colored "  [!] Failed to install $tool" "$RED"
                    ;;
            esac
        else
            print_colored "  [+] $tool is already installed" "$GREEN"
        fi
    done
}

# Run installation functions
install_dependencies
install_tools


# Initialize colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
RESET='\033[0m'

# Function to print colored text
print_colored() {
    local text=$1
    local color=$2
    if [[ -z $color ]]; then
        colors=("$GREEN" "$BLUE" "$YELLOW" "$MAGENTA" "$CYAN")
        color=${colors[$RANDOM % ${#colors[@]}]}
    fi
    echo -e "${color}${text}${RESET}"
}

# Function to count results and remove duplicates
count_results() {
    local file=$1
    local tool_name=$2
    if [[ -f "$file" ]]; then
        local count=$(sort "$file" | uniq | wc -l)
        print_colored "  [+] ${tool_name} result is: ${count}" "$GREEN"
    else
        print_colored "  [-] No results found for ${tool_name}" "$RED"
    fi
}

# Function to set up output directory
setup_output_directory() {
    local target=$1
    local timestamp=$(date +"%Y%m%d_%H%M%S")
    local output_dir="${target}_${timestamp}"
    mkdir -p "$output_dir"
    mkdir -p "${output_dir}/subdomains"
    mkdir -p "${output_dir}/ips"
    mkdir -p "${output_dir}/asns"
    mkdir -p "${output_dir}/cidrs"
    mkdir -p "${output_dir}/urls"
    mkdir -p "${output_dir}/js"
    mkdir -p "${output_dir}/params"
    echo "$output_dir"
}

# Function to check if a tool is installed
check_tool() {
    local tool=$1
    if ! command -v "$tool" &> /dev/null; then
        print_colored "  [-] Warning: $tool is not installed or not in PATH" "$RED"
        return 1
    fi
    return 0
}

# Function to run a shell command, display output, and save to file
# Function to run a shell command, display output, and save to file
run_command() {
    local tool=$1
    shift
    local output_file=$1
    shift
    local display=$1
    shift

    if [[ -z $display ]]; then
        display=true
    fi

    if ! check_tool "$tool"; then
        return
    fi

    # عرض رسالة "running [tool name]" قبل تشغيل الأداة
    print_colored "  [+] running $tool" "$YELLOW"

    # تنظيف الناتج من البايتات الفارغة
    output=$("$@" 2>&1 | tr -d '\0')
    if [[ $? -eq 0 ]]; then
        if [[ -n $output_file ]]; then
            echo "$output" > "$output_file"
        fi
        if [[ $count_only -eq 1 && $display == true ]]; then
            if [[ -f "$output_file" ]]; then
                local count=$(wc -l < "$output_file")
                print_colored "  [+] $tool result is: $count" "$GREEN"
            else
                print_colored "  [-] No results found for $tool" "$RED"
            fi
        elif [[ $display == true && $count_only -ne 1 ]]; then
            while IFS= read -r line; do
                print_colored "  [+] $line"
            done <<< "$output"
        fi
        echo "$output"
    else
        if [[ -n $output && $display == true && $count_only -ne 1 ]]; then
            print_colored "  [-] Error: $output" "$RED"
        fi
    fi
}

# Function to combine and get unique subdomains
get_unique_subdomains() {
    local output_dir=$1
    local subdomains_dir="${output_dir}/subdomains"
    local unique_file="${output_dir}/unique_subdomains.txt"

    mkdir -p "$subdomains_dir"
    if ls "${subdomains_dir}"/*.txt 1> /dev/null 2>&1; then
        cat "${subdomains_dir}"/*.txt | sort | uniq > "$unique_file"
        local unique_count=$(wc -l < "$unique_file")
        if [[ $count_only -ne 1 ]]; then
            print_colored "  [+] Unique Subdomains Found: ${unique_count}" "$GREEN"
        fi
    else
        if [[ $count_only -ne 1 ]]; then
            print_colored "  [-] No subdomain files found to combine" "$RED"
        fi
    fi
    echo "$unique_file"
}

# Wilde Mode Recon
run_wilde_mode() {
    local target=$1
    local subdomain_wordlist=$2
    local output_dir=$3

    print_colored "Now you are using Wilde Mode (Focus: IPs, ASNs, CIDRs, Subdomain Enumeration, Subdomain Brute Forcing)" "$YELLOW"

    print_colored "Step 9: Subdomain Enumeration" "$BLUE"
    run_command subfinder "${output_dir}/subdomains/subdomains_subfinder.txt" true subfinder -d "${target}" -all -o "${output_dir}/subdomains/subdomains_subfinder.txt"
    run_command amass "${output_dir}/subdomains/subdomains_amass.txt" true amass enum -brute -active -d "${target}" -o "${output_dir}/subdomains/subdomains_amass.txt"
    run_command curl "${output_dir}/subdomains/subdomains_crtsh.txt" true curl -s "https://crt.sh/?q=%25.${target}" | grep -oE '[\.a-zA-Z0-9-]+\.${target}' | sort -u > "${output_dir}/subdomains/subdomains_crtsh.txt"
    run_command theHarvester "${output_dir}/subdomains/subdomains_theharvester.txt" true theHarvester -d "${target}" -b all -f "${output_dir}/subdomains/subdomains_theharvester.txt"
  run_command subenum "${output_dir}/subdomains/subdomains_subenum.txt" true subenum -d "${target}" -o "${output_dir}/subdomains/subdomains_subenum.txt"
   run_command findomain "${output_dir}/subdomains/subdomains_findomain.txt" true findomain -d "${target}" -o "${output_dir}/subdomains/subdomains_findomain.txt"
   run_command assetfinder "${output_dir}/subdomains/subdomains_assetfinder.txt" true assetfinder --subs-only "${target}" > "${output_dir}/subdomains/subdomains_assetfinder.txt"
   run_command sublist3r "${output_dir}/subdomains/subdomains_sublist3r.txt" true sublist3r -d "${target}" -o "${output_dir}/subdomains/subdomains_sublist3r.txt"
    run_command massdns "${output_dir}/subdomains/subdomains_massdns.txt" true massdns -r resolvers.txt -t A -o S -w "${output_dir}/subdomains/subdomains_massdns.txt" "${target}.txt"
    run_command shodan "${output_dir}/subdomains/subdomains_shodan.txt" true shodan domain "${target}" > "${output_dir}/subdomains/subdomains_shodan.txt"
    run_command curl "${output_dir}/subdomains/subdomains_vt.txt" true curl -s "https://www.virustotal.com/vtapi/v2/domain/report?apikey=${vt_api_key}&domain=${target}" | jq -r '.domain_siblings[]' > "${output_dir}/subdomains/subdomains_vt.txt"
    run_command chaos "${output_dir}/subdomains/subdomains_chaos.txt" true chaos -d "${target}" -o "${output_dir}/subdomains/subdomains_chaos.txt"
    run_command curl "${output_dir}/subdomains/subdomains_securitytrails.txt" true curl -s "https://api.securitytrails.com/v1/domain/${target}/subdomains?apikey=YOUR_API_KEY" > "${output_dir}/subdomains/subdomains_securitytrails.txt"
    run_command spyse "${output_dir}/subdomains/subdomains_spyse.txt" true spyse -t domain -q "${target}" -o "${output_dir}/subdomains/subdomains_spyse.txt"
    run_command urlscan "${output_dir}/subdomains/subdomains_urlscan.txt" true urlscan -d "${target}" -o "${output_dir}/subdomains/subdomains_urlscan.txt"
    run_command zoomeye "${output_dir}/subdomains/subdomains_zoomeye.txt" true zoomeye search "domain:${target}" -o "${output_dir}/subdomains/subdomains_zoomeye.txt"
    run_command censys "${output_dir}/subdomains/subdomains_censys.txt" true censys search "parsed.names: ${target}" --index certificates -o "${output_dir}/subdomains/subdomains_censys.txt"
    run_command dnsrecon "${output_dir}/subdomains/subdomains_dnsrecon.csv" true dnsrecon -d "${target}" -t brt -D "${subdomain_wordlist}" -c "${output_dir}/subdomains/subdomains_dnsrecon.csv"
    run_command knockpy "${output_dir}/subdomains/subdomains_knockpy.txt" true knockpy "${target}" -o "${output_dir}/subdomains/subdomains_knockpy.txt"
    run_command frogy "${output_dir}/subdomains/subdomains_frogy.txt" true frogy -d "${target}" -o "${output_dir}/subdomains/subdomains_frogy.txt"
    run_command github-subdomains "${output_dir}/subdomains/subdomains_github.txt" true github-subdomains -d "${target}" -t GITHUB_TOKEN -o "${output_dir}/subdomains/subdomains_github.txt"
    run_command gitlab-subdomains "${output_dir}/subdomains/subdomains_gitlab.txt" true gitlab-subdomains -d "${target}" -t GITLAB_TOKEN -o "${output_dir}/subdomains/subdomains_gitlab.txt"
    run_command alterx "${output_dir}/subdomains/subdomains_alterx.txt" true alterx -l domains.txt -o "${output_dir}/subdomains/subdomains_alterx.txt"
    run_command python3 "${output_dir}/subdomains/subdomains_oneforall.txt" true python3 oneforall.py --target "${target}" run -o "${output_dir}/subdomains/subdomains_oneforall.txt"
    run_command domainCollector "${output_dir}/subdomains/subdomains_domaincollector.txt" true domainCollector -d "${target}" -o "${output_dir}/subdomains/subdomains_domaincollector.txt"
    run_command openssl "${output_dir}/subdomains/subdomains_openssl.txt" true echo | openssl s_client -connect "${target}:443" -servername "${target}" 2>/dev/null | openssl x509 -noout -subject -issuer -ext subjectAltName > "${output_dir}/subdomains/subdomains_openssl.txt"

    print_colored "Step 10: Subdomain Brute Forcing" "$BLUE"
    run_command shuffledns "${output_dir}/subdomains/subdomains_shuffledns.txt" true shuffledns -d "${target}" -w "${subdomain_wordlist}" -r resolvers.txt -o "${output_dir}/subdomains/subdomains_shuffledns.txt"
    run_command gobuster "${output_dir}/subdomains/subdomains_gobuster.txt" true gobuster dns -d "${target}" -t 50 -w "${subdomain_wordlist}" -o "${output_dir}/subdomains/subdomains_gobuster.txt"
    run_command dnscan.py "${output_dir}/subdomains/subdomains_dnscan.txt" true dnscan.py -d "dev-*.${target}" -o "${output_dir}/subdomains/subdomains_dnscan.txt"

    unique_subdomains_file=$(get_unique_subdomains "$output_dir")
    if [[ -f "$unique_subdomains_file" ]]; then
        if [[ $count_only -ne 1 ]]; then
            print_colored "Using unique subdomains file: ${unique_subdomains_file}" "$YELLOW"
        fi
        run_command httprobe "${output_dir}/live_httprobe.txt" true cat "${unique_subdomains_file}" | httprobe > "${output_dir}/live_httprobe.txt"
        run_command httpx "${output_dir}/live_httpx.txt" true cat "${unique_subdomains_file}" | httpx -sc -ip -server -title -wc -o "${output_dir}/live_httpx.txt"
    fi

    if [[ $count_only -eq 1 ]]; then
        print_colored "Results Count for Each Tool:" "$YELLOW"
        count_results "${output_dir}/subdomains/subdomains_subfinder.txt" "Subfinder"
        count_results "${output_dir}/subdomains/subdomains_amass.txt" "Amass"
        count_results "${output_dir}/subdomains/subdomains_crtsh.txt" "CRT.sh"
        count_results "${output_dir}/subdomains/subdomains_theharvester.txt" "TheHarvester"
        count_results "${output_dir}/subdomains/subdomains_subenum.txt" "Subenum"
        count_results "${output_dir}/subdomains/subdomains_findomain.txt" "Findomain"
        count_results "${output_dir}/subdomains/subdomains_assetfinder.txt" "Assetfinder"
        count_results "${output_dir}/subdomains/subdomains_sublist3r.txt" "Sublist3r"
        count_results "${output_dir}/subdomains/subdomains_massdns.txt" "MassDNS"
        count_results "${output_dir}/subdomains/subdomains_shodan.txt" "Shodan"
        count_results "${output_dir}/subdomains/subdomains_vt.txt" "VirusTotal"
        count_results "${output_dir}/subdomains/subdomains_chaos.txt" "Chaos"
        count_results "${output_dir}/subdomains/subdomains_securitytrails.txt" "SecurityTrails"
        count_results "${output_dir}/subdomains/subdomains_spyse.txt" "Spyse"
        count_results "${output_dir}/subdomains/subdomains_urlscan.txt" "URLScan"
        count_results "${output_dir}/subdomains/subdomains_zoomeye.txt" "ZoomEye"
        count_results "${output_dir}/subdomains/subdomains_censys.txt" "Censys"
        count_results "${output_dir}/subdomains/subdomains_dnsrecon.csv" "DNSRecon"
        count_results "${output_dir}/subdomains/subdomains_knockpy.txt" "Knockpy"
        count_results "${output_dir}/subdomains/subdomains_frogy.txt" "Frogy"
        count_results "${output_dir}/subdomains/subdomains_github.txt" "GitHub Subdomains"
        count_results "${output_dir}/subdomains/subdomains_gitlab.txt" "GitLab Subdomains"
        count_results "${output_dir}/subdomains/subdomains_alterx.txt" "AlterX"
        count_results "${output_dir}/subdomains/subdomains_oneforall.txt" "OneForAll"
        count_results "${output_dir}/subdomains/subdomains_domaincollector.txt" "DomainCollector"
        count_results "${output_dir}/subdomains/subdomains_openssl.txt" "OpenSSL"
        count_results "${output_dir}/subdomains/subdomains_shuffledns.txt" "ShuffleDNS"
        count_results "${output_dir}/subdomains/subdomains_gobuster.txt" "Gobuster DNS"
        count_results "${output_dir}/subdomains/subdomains_dnscan.txt" "DNScan"
        count_results "${output_dir}/live_httprobe.txt" "Httprobe"
        count_results "${output_dir}/live_httpx.txt" "Httpx"
    fi
}

# Open Mode Recon
run_open_mode() {
    local target=$1
    local subdomain_wordlist=$2
    local vhost_wordlist=$3
    local output_dir=$4

    print_colored "Now you are using Open Mode (Full Reconnaissance)" "$YELLOW"

    print_colored "Step 3: Virtual Host Fuzzing" "$BLUE"
    run_command gobuster "${output_dir}/vhosts_gobuster.txt" true gobuster vhost -u "https://${target}" -t 50 -w "${vhost_wordlist}" --no-error -r -q --append-domain -o "${output_dir}/vhosts_gobuster.txt"
    run_command VHostScan "${output_dir}/vhosts_vhostscan.txt" true VHostScan -t "${target}" --scan-new -s --force-ssl --threads 50 --no-status-check -o "${output_dir}/vhosts_vhostscan.txt"

    run_wilde_mode "$target" "$subdomain_wordlist" "$output_dir"
    run_urls_mode "$target" "$subdomain_wordlist" "$vhost_wordlist" "$output_dir"

    if [[ $count_only -eq 1 ]]; then
        print_colored "Results Count for Virtual Host Fuzzing Tools:" "$YELLOW"
        count_results "${output_dir}/vhosts_gobuster.txt" "Gobuster VHost"
        count_results "${output_dir}/vhosts_vhostscan.txt" "VHostScan"
    fi
}

# Urls Mode Recon
run_urls_mode() {
    local target=$1
    local subdomain_wordlist=$2
    local vhost_wordlist=$3
    local output_dir=$4

    print_colored "Now you are using Urls Mode (Focus: URL and JS Enumeration)" "$YELLOW"

    print_colored "Step 16: Claim URLs" "$BLUE"
    run_command katana "${output_dir}/urls_katana.txt" true katana -u "https://${target}" -o "${output_dir}/urls_katana.txt"
    run_command gospider "${output_dir}/urls_gospider.txt" true gospider -s "https://${target}/" -o "${output_dir}/urls_gospider.txt" -c 10 -d 1
    run_command gau "${output_dir}/urls_gau.txt" true echo "${target}" | gau -subs -o "${output_dir}/urls_gau.txt"
    run_command waybackurls "${output_dir}/urls_waybackurls.txt" true echo "${target}" | waybackurls -o "${output_dir}/urls_waybackurls.txt"
    run_command hakrawler "${output_dir}/urls_hakrawler.txt" true echo "https://${target}" | hakrawler -o "${output_dir}/urls_hakrawler.txt"

    print_colored "Step 17: Scan JS Files" "$BLUE"
    if [[ -f js-urls.txt ]]; then
        run_command hakcheckurl "${output_dir}/js_hakcheckurl.txt" true cat js-urls.txt | hakcheckurl -o "${output_dir}/js_hakcheckurl.txt"
    else
        if [[ $count_only -ne 1 ]]; then
            print_colored "  [-] js-urls.txt not found" "$RED"
        fi
    fi
    run_command python3 "${output_dir}/js_linkfinder.txt" true python3 linkfinder.py -i "https://${target}/script.js" -o "${output_dir}/js_linkfinder.txt"
    if [[ -f js-files.txt ]]; then
        run_command python3 "${output_dir}/js_dumpsterdiver.txt" true python3 DumpsterDiver.py -p js-files.txt -o "${output_dir}/js_dumpsterdiver.txt"
    else
        if [[ $count_only -ne 1 ]]; then
            print_colored "  [-] js-files.txt not found" "$RED"
        fi
    fi

    print_colored "Step 18: Hidden Parameters" "$BLUE"
    run_command ffuf "${output_dir}/params_ffuf.txt" true ffuf -w "${subdomain_wordlist}" -u "https://${target}/script.php?FUZZ=test_value" -fs 4242 -o "${output_dir}/params_ffuf.txt"
    run_command arjun "${output_dir}/params_arjun.txt" true arjun -u "https://${target}/endpoint" -o "${output_dir}/params_arjun.txt"
    run_command python3 "${output_dir}/params_paramspider.txt" true python3 paramspider.py -d "${target}" -o "${output_dir}/params_paramspider.txt"

    if [[ $count_only -eq 1 ]]; then
        print_colored "Results Count for Each Tool:" "$YELLOW"
        count_results "${output_dir}/urls_katana.txt" "Katana"
        count_results "${output_dir}/urls_gospider.txt" "GoSpider"
        count_results "${output_dir}/urls_gau.txt" "GAU"
        count_results "${output_dir}/urls_waybackurls.txt" "Waybackurls"
        count_results "${output_dir}/urls_hakrawler.txt" "Hakrawler"
        count_results "${output_dir}/js_hakcheckurl.txt" "Hakcheckurl"
        count_results "${output_dir}/js_linkfinder.txt" "LinkFinder"
        count_results "${output_dir}/js_dumpsterdiver.txt" "DumpsterDiver"
        count_results "${output_dir}/params_ffuf.txt" "FFuF"
        count_results "${output_dir}/params_arjun.txt" "Arjun"
        count_results "${output_dir}/params_paramspider.txt" "ParamSpider"
    fi
}

# Main Recon Function
run_recon() {
    local mode="Unknown"
    local targets=()

    if [[ $wilde_mode -eq 1 ]]; then
        mode="wilde"
    elif [[ $open_mode -eq 1 ]]; then
        mode="open"
    elif [[ $urls_mode -eq 1 ]]; then
        mode="urls"
    fi

    if [[ -n $domain ]]; then
        targets=("$domain")
        print_colored "Target Domain: ${domain}" "$GREEN"
    elif [[ -n $target_file ]]; then
        mapfile -t targets < "$target_file"
        print_colored "Targets from file: ${target_file} (${#targets[@]} lines)" "$GREEN"
    else
        print_colored "Error: Please provide either -d or -t" "$RED"
        exit 1
    fi

    print_colored "Current Mode: ${mode}" "$YELLOW"
    print_colored "Created By Ahmex000" "$GREEN"

    for target in "${targets[@]}"; do
        output_dir=$(setup_output_directory "$target")
        print_colored "Output Directory: ${output_dir}" "$GREEN"
        if [[ $mode == "wilde" ]]; then
            run_wilde_mode "$target" "$subdomain_wordlist" "$output_dir"
        elif [[ $mode == "open" ]]; then
            run_open_mode "$target" "$subdomain_wordlist" "$vhost_wordlist" "$output_dir"
        elif [[ $mode == "urls" ]]; then
            run_urls_mode "$target" "$subdomain_wordlist" "$vhost_wordlist" "$output_dir"
        fi
    done
}

# Argument Parsing
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                echo "Usage: Y-Recon.sh [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  -d, --domain <target>      Set target domain"
                echo "  -t, --target-file <file>   Provide a file containing targets"
                echo "  -wilde                     Use Wilde Mode (IPs, ASN, CIDRs, etc.)"
                echo "  -open                      Use Open Mode (Full Recon)"
                echo "  -urls                      Use URLs Mode (URL and JS enumeration)"
                echo "  -s, --subdomain-wordlist   Set subdomain wordlist"
                echo "  -v, --vhost-wordlist       Set virtual host wordlist (required for open mode)"
                echo "  -c, --count-only           Display only the count of results"
                echo "  -h, --help                 Show this help message"
                exit 0
                ;;
            -d|--domain)
                domain=$2
                shift 2
                ;;
            -t|--target-file)
                target_file=$2
                shift 2
                ;;
            -wilde)
                wilde_mode=1
                shift
                ;;
            -open)
                open_mode=1
                shift
                ;;
            -urls)
                urls_mode=1
                shift
                ;;
            -s|--subdomain-wordlist)
                subdomain_wordlist=$2
                shift 2
                ;;
            -v|--vhost-wordlist)
                vhost_wordlist=$2
                shift 2
                ;;
            -c|--count-only)
                count_only=1
                shift
                ;;
            *)
                echo "Unknown option: $1"
                echo "Use -h or --help for usage information."
                exit 1
                ;;
        esac
    done

    if [[ -z $domain && -z $target_file ]]; then
        echo "Error: Please provide either -d or -t"
        exit 1
    fi

    if [[ -z $wilde_mode && -z $open_mode && -z $urls_mode ]]; then
        echo "Error: Please provide a mode (-wilde, -open, -urls)"
        exit 1
    fi

    if [[ -z $subdomain_wordlist ]]; then
        echo "Error: You must provide a subdomain wordlist (-s <file>) for Wilde or Open mode."
        exit 1
    fi

    if [[ $open_mode -eq 1 && -z $vhost_wordlist ]]; then
        echo "Error: Please provide -v (vhost wordlist) for open mode"
        exit 1
    fi
}

# Main Execution
parse_arguments "$@"
run_recon
