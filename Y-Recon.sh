#!/bin/bash

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
    mkdir -p "${output_dir}/TLD"
    echo "$output_dir"
}

# Function to check if a tool is installed
check_tool() {
    local tool=$1
    if ! command -v "$tool" &>/dev/null; then
        print_colored "  [-] Warning: $tool is not installed or not in PATH" "$RED"
        return 1
    fi
    return 0
}

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
            echo "$output" >"$output_file"
        fi
        if [[ $count_only -eq 1 && $display == true ]]; then
            if [[ -f "$output_file" ]]; then
                local count=$(wc -l <"$output_file")
                print_colored "  [+] $tool result is: $count" "$GREEN"
            else
                print_colored "  [-] No results found for $tool" "$RED"
            fi
        elif [[ $display == true && $count_only -ne 1 ]]; then
            while IFS= read -r line; do
                print_colored "  [+] $line"
            done <<<"$output"
        fi
        echo "$output"
    else
        if [[ -n $output && $display == true && $count_only -ne 1 ]]; then
            print_colored "  [-] Error: $output" "$RED"
        fi
    fi
}

# Wilde Mode Recon
run_wilde_mode() {
    local target=$1
    local subdomain_wordlist=$2
    local output_dir=$3

    print_colored "2 - Now you are using Wilde Mode (Focus: IPs, ASNs, CIDRs, Subdomain Enumeration, Subdomain Brute Forcing)" "$YELLOW"

    print_colored "Step 9: Subdomain Enumeration" "$BLUE"
    echo "now use subfinder and output file is ${output_dir}/subdomains/subdomains_subfinder.txt & input file is ${target}"
    run_command subfinder "${output_dir}/subdomains/subdomains_subfinder.txt" false subfinder -silent -d "${target}" -all -o "${output_dir}/subdomains/subdomains_subfinder.txt"
    echo "now use amass and output file is ${output_dir}/subdomains/subdomains_amass.txt & input file is ${target}"
    run_command amass "${output_dir}/subdomains/subdomains_amass.txt" false amass enum -brute -active -ip -brute -min-for-recursive -d "${target}" -o "${output_dir}/subdomains/subdomains_amass.txt"
    echo "now use curl to fetch from crt.sh and output file is ${output_dir}/subdomains/subdomains1_crtsh.txt & input file is ${target}"
    run_command curl "${output_dir}/subdomains/subdomains_crtsh.txt" false bash -c "curl -s 'https://crt.sh/?q=%25.${target}&output=json' | jq -r '.[].name_value' | tr ' ' '\n' | sed 's/^\*\.//g' >> '${output_dir}/subdomains/subdomains1_crtsh.txt'"

    echo "now use curl to fetch from crt.sh and output file is ${output_dir}/subdomains/subdomains2_crtsh.txt & input file is ${target}"
    run_command curl "${output_dir}/subdomains/subdomains_crtsh.txt" true bash -c "curl -s 'https://crt.sh/?q=%25.%25.${target}&output=json' | jq -r '.[].name_value' | tr ' ' '\n' | sed 's/^\*\.//g' >> '${output_dir}/subdomains/subdomains2_crtsh.txt'"

    echo "now use curl to fetch from crt.sh and output file is ${output_dir}/subdomains/subdomains3_crtsh.txt & input file is ${target}"
    run_command curl "${output_dir}/subdomains/subdomains_crtsh.txt" true bash -c "curl -s 'https://crt.sh/?q=%25.%25.%25.${target}&output=json' | jq -r '.[].name_value' | tr ' ' '\n' | sed 's/^\*\.//g' >> '${output_dir}/subdomains/subdomains3_crtsh.txt'"

    echo "now use subenum and output file is ${output_dir}/subdomains/subdomains_subenum.txt & input file is ${target}"
    run_command subenum "${output_dir}/subdomains/subdomains_subenum.txt" true subenum -d "${target}" -o "${output_dir}/subdomains/subdomains_subenum.txt"
    echo "now use findomain and output file is ${output_dir}/subdomains/subdomains_findomain.txt & input file is ${target}"
    run_command findomain "${output_dir}/subdomains/subdomains_findomain.txt" true findomain -t "${target}" -o "${output_dir}/subdomains/subdomains_findomain.txt"
    echo "now use assetfinder and output file is ${output_dir}/subdomains/subdomains_assetfinder.txt & input file is ${target}"
    run_command assetfinder "${output_dir}/subdomains/subdomains_assetfinder.txt" true assetfinder --subs-only "${target}" >"${output_dir}/subdomains/subdomains_assetfinder.txt"
    echo "now use sublist3r and output file is ${output_dir}/subdomains/subdomains_sublist3r.txt & input file is ${target}"
    run_command sublist3r "${output_dir}/subdomains/subdomains_sublist3r.txt" true sublist3r -d "${target}" -o "${output_dir}/subdomains/subdomains_sublist3r.txt"
    echo "now use massdns and output file is ${output_dir}/subdomains/subdomains_massdns.txt & input file is ${target}.txt"
    run_command massdns "${output_dir}/subdomains/subdomains_massdns.txt" true massdns -r resolvers.txt -t A -o S -w "${output_dir}/subdomains/subdomains_massdns.txt" "${target}.txt"
    echo "now use shodan and output file is ${output_dir}/subdomains/subdomains_shodan.txt & input file is ${target}"
    run_command shodan "${output_dir}/subdomains/subdomains_shodan.txt" true shodan domain "${target}" >"${output_dir}/subdomains/subdomains_shodan.txt"
    echo "now use curl to fetch from www.virustotal.com and output file is ${output_dir}/subdomains/subdomains_vt.txt & input file is ${target}"
    run_command curl "${output_dir}/subdomains/subdomains_vt.txt" true curl -s "https://www.virustotal.com/vtapi/v2/domain/report?apikey=${vt_api_key}&domain=${target}" | jq -r '.domain_siblings[]' >"${output_dir}/subdomains/subdomains_vt.txt"
    echo "now use chaos and output file is ${output_dir}/subdomains/subdomains_chaos.txt & input file is ${target}"
    run_command chaos "${output_dir}/subdomains/subdomains_chaos.txt" true chaos -d "${target}" -o "${output_dir}/subdomains/subdomains_chaos.txt"
    echo "now use curl to fetch from api.securitytrails.com and output file is ${output_dir}/subdomains/subdomains_securitytrails.txt & input file is ${target}"
    run_command curl "${output_dir}/subdomains/subdomains_securitytrails.txt" true curl -s "https://api.securitytrails.com/v1/domain/${target}/subdomains?apikey=YOUR_API_KEY" >"${output_dir}/subdomains/subdomains_securitytrails.txt"
    echo "now use spyse and output file is ${output_dir}/subdomains/subdomains_spyse.txt & input file is ${target}"
    run_command spyse "${output_dir}/subdomains/subdomains_spyse.txt" true spyse -t domain -q "${target}" -o "${output_dir}/subdomains/subdomains_spyse.txt"
    echo "now use urlscan and output file is ${output_dir}/subdomains/subdomains_urlscan.txt & input file is ${target}"
    run_command urlscan "${output_dir}/subdomains/subdomains_urlscan.txt" true urlscan -d "${target}" -o "${output_dir}/subdomains/subdomains_urlscan.txt"
    echo "now use zoomeye and output file is ${output_dir}/subdomains/subdomains_zoomeye.txt & input file is ${target}"
    run_command zoomeye "${output_dir}/subdomains/subdomains_zoomeye.txt" true zoomeye search "domain:${target}" -o "${output_dir}/subdomains/subdomains_zoomeye.txt"
    echo "now use censys and output file is ${output_dir}/subdomains/subdomains_censys.txt & input file is ${target}"
    run_command censys "${output_dir}/subdomains/subdomains_censys.txt" true censys search "parsed.names: ${target}" --index certificates -o "${output_dir}/subdomains/subdomains_censys.txt"
    echo "now use dnsrecon and output file is ${output_dir}/subdomains/subdomains_dnsrecon.csv & input file is ${subdomain_wordlist}"
    run_command dnsrecon "${output_dir}/subdomains/subdomains_dnsrecon.csv" true dnsrecon -d "${target}" -t brt -D "${subdomain_wordlist}" -c "${output_dir}/subdomains/subdomains_dnsrecon.csv"
    echo "now use knockpy and output file is ${output_dir}/subdomains/subdomains_knockpy.txt & input file is ${target}"
    run_command knockpy "${output_dir}/subdomains/subdomains_knockpy.txt" true knockpy "${target}" -o "${output_dir}/subdomains/subdomains_knockpy.txt"
    echo "now use frogy and output file is ${output_dir}/subdomains/subdomains_frogy.txt & input file is ${target}"
    run_command frogy "${output_dir}/subdomains/subdomains_frogy.txt" true frogy -d "${target}" -o "${output_dir}/subdomains/subdomains_frogy.txt"
    echo "now use github-subdomains and output file is ${output_dir}/subdomains/subdomains_github.txt & input file is ${target}"
    run_command github-subdomains "${output_dir}/subdomains/subdomains_github.txt" true github-subdomains -d "${target}" -t GITHUB_TOKEN -o "${output_dir}/subdomains/subdomains_github.txt"
    echo "now use gitlab-subdomains and output file is ${output_dir}/subdomains/subdomains_gitlab.txt & input file is ${target}"
    run_command gitlab-subdomains "${output_dir}/subdomains/subdomains_gitlab.txt" true gitlab-subdomains -d "${target}" -t GITLAB_TOKEN -o "${output_dir}/subdomains/subdomains_gitlab.txt"
    echo "now use alterx and output file is ${output_dir}/subdomains/subdomains_alterx.txt & input file is domains.txt"
    run_command alterx "${output_dir}/subdomains/subdomains_alterx.txt" true alterx -l domains.txt -o "${output_dir}/subdomains/subdomains_alterx.txt"
    echo "now use python3 and output file is ${output_dir}/subdomains/subdomains_oneforall.txt & input file is ${target}"
    run_command python3 "${output_dir}/subdomains/subdomains_oneforall.txt" true python3 oneforall.py --target "${target}" run -o "${output_dir}/subdomains/subdomains_oneforall.txt"
    echo "now use domainCollector and output file is ${output_dir}/subdomains/subdomains_domaincollector.txt & input file is ${target}"
    run_command domainCollector "${output_dir}/subdomains/subdomains_domaincollector.txt" true domainCollector -d "${target}" -o "${output_dir}/subdomains/subdomains_domaincollector.txt"
    echo "now use openssl and output file is ${output_dir}/subdomains/subdomains_openssl.txt & input file is ${target}"
    run_command openssl "${output_dir}/subdomains/subdomains_openssl.txt" true echo | openssl s_client -connect "${target}:443" -servername "${target}" 2>/dev/null | openssl x509 -noout -subject -issuer -ext subjectAltName >"${output_dir}/subdomains/subdomains_openssl.txt"

    print_colored "Step 10: Subdomain Brute Forcing" "$BLUE"
    echo "now use shuffledns and output file is ${output_dir}/subdomains/subdomains_shuffledns.txt & input file is ${subdomain_wordlist}"
    run_command shuffledns "${output_dir}/subdomains/subdomains_shuffledns.txt" true shuffledns -d "${target}" -w "${subdomain_wordlist}" -r resolvers.txt -o "${output_dir}/subdomains/subdomains_shuffledns.txt"
    echo "now use gobuster and output file is ${output_dir}/subdomains/subdomains_gobuster.txt & input file is ${subdomain_wordlist}"
    run_command gobuster "${output_dir}/subdomains/subdomains_gobuster.txt" true gobuster dns -d "${target}" -t 50 -w "${subdomain_wordlist}" -o "${output_dir}/subdomains/subdomains_gobuster.txt"
    echo "now use dnscan.py and output file is ${output_dir}/subdomains/subdomains_dnscan.txt & input file is ${target}"
    run_command dnscan.py "${output_dir}/subdomains/subdomains_dnscan.txt" true dnscan.py -d "dev-*.${target}" -o "${output_dir}/subdomains/subdomains_dnscan.txt"

    cat "${output_dir}/subdomains/"* | sort -u >"${output_dir}/subdomains/unique_subdomains.txt"
    cat "${output_dir}/subdomains/unique_subdomains.txt" | httpx -sc -ip -server -title -wc -fr -p 80,443,8080,8000,8888 -o "${output_dir}/subdomains/live_subdomains.txt"

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
echo -e "\n\n-----------------------------------------------------------------\n\n"

run_open_mode() {
    local target=$1
    local subdomain_wordlist=$2
    local vhost_wordlist=$3
    local output_dir=$4

    base_domain="${target%%.*}"

    print_colored "Now you are using Open Mode (Full Reconnaissance)" "$YELLOW"

    # Claim TLD's
    echo "send curl to crt.sh to claim TLDs"
    run_command "curl" "${output_dir}/subdomains/subdomains_crtsh.txt" true \
        bash -c "curl -s 'https://crt.sh/?q=%25.${base_domain}&output=json' | jq -r '.[].name_value' | tr ' ' '\n' | sed 's/^\*\.//g' | grep -v '^${target}$' > '${output_dir}/TLD/${base_domain}_TLD.txt'"

    echo -e "\n\n-----------------------------------------------------------------\n\n"

    # Brute Forcing Vhosts using VHostScan

    print_colored "Virtual Host Fuzzing" "$BLUE"
    run_command VHostScan "${output_dir}/vhosts_vhostscan.txt" true VHostScan -t "https://${target}" -w "${vhost_wordlist}" --ssl -oN "${output_dir}/vhosts_vhostscan.txt"
    if [[ $count_only -eq 1 ]]; then
        print_colored "Results Count for Virtual Host Fuzzing Tools:" "$YELLOW"
        count_results "${output_dir}/vhosts_gobuster.txt" "Gobuster VHost"
        count_results "${output_dir}/vhosts_vhostscan.txt" "VHostScan"
    fi

    run_command gobuster "${output_dir}/vhosts_gobuster.txt" true gobuster vhost -u "https://${target}" -t 50 -w "${vhost_wordlist}" --no-error -r -q --append-domain -o "${output_dir}/vhosts_gobuster.txt"

    echo -e "\n\n-----------------------------------------------------------------\n\n"

    # Resolve DNS (DNS) :  Domains to IPs via DIG
    echo "Resolve DNS (DNS) :  Domains to IPs via DIG"
    # Here when i resolve Domain to IP , i will Reverse DNS , and gain all Domains Hosted in this IP .

    # List Of alll hosting provider's IP patterns
    #3.0.0.0/8,13.0.0.0/8,15.0.0.0/8,18.0.0.0/8,34.0.0.0/8,44.192.0.0/10,52.0.0.0/8,54.0.0.0/8,99.0.0.0/8,103.21.244.0/22,103.22.200.0/22,103.31.4.0/22,104.16.0.0/13,104.24.0.0/14,172.64.0.0/13,8.8.8.0/24,34.64.0.0/10,35.190.0.0/16,35.191.0.0/16,66.102.0.0/20,66.249.64.0/19,23.32.0.0/11,23.48.0.0/14,23.72.0.0/13,23.204.0.0/14,151.101.0.0/16,167.82.0.0/17,199.27.72.0/21,45.60.0.0/16,45.223.0.0/16,103.28.248.0/22,64.62.128.0/18,138.68.0.0/16,159.203.0.0/16,192.241.128.0/17,13.64.0.0/11,40.64.0.0/10,52.232.0.0/14,104.40.0.0/13,5.39.0.0/17,37.187.0.0/16,46.105.0.0/16,91.121.0.0/16,144.76.0.0/16,148.251.0.0/16,176.9.0.0/16,213.239.192.0/18,50.116.0.0/16,96.126.96.0/19,173.255.192.0/18,192.81.128.0/17

    # Resolve DNS (DNS) :  Domains to IPs via DIG
    run_command dig "${output_dir}/ips/dns_lookup.txt" true dig +short "${target}" >"${output_dir}/temp.txt"
    cat "${output_dir}/temp.txt" | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/' | anew >"${output_dir}/ips/dns_lookup.txt"
    rm "${output_dir}/temp.txt"
    cat "${output_dir}/ips/"* | anew >"${output_dir}/ips/uniqe_IPs.txt"
    print_colored "Do Revers DNS (rDNS): Resolve IP's To Domains MANUAL " "$YELLOW"

    # Revers DNS (DNS) :  IPs to Domains via DIG
    cat "${output_dir}/ips/uniqe_IPs.txt" | while read -r ip; do
        curl -s "https://api.shodan.io/shodan/host/${ip}?key=3sSinAybgTpzxdjVM9au6A6SmhVHJ181" | tee \
            >(jq -r '.data[].domains[]' | sort -u >>"${output_dir}/subdomains/rDNS.txt") \
            >(jq -r '.asn' | sort -u >>"${output_dir}/asns/asns_shodan.txt")
    done
    cat "${output_dir}/asns/"* | anew >"${output_dir}/asns/unique_asns.txt"

    echo -e "\n-----------------------------------------------------------------\n"

    echo "Claiming CIDR's"
    cat "${output_dir}/ips/uniqe_IPs.txt" | while read -r ip; do
        [[ -n "$ip" ]] && whois "$ip" | tee \
            >(grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]+' | sort -u >>"${output_dir}/cidrs/whois_cidrs.txt")
    done

    echo -e "\n-----------------------------------------------------------------\n"
    echo "resolve ASNS to CIDR's"

    cat "${output_dir}/asns/unique_asns.txt" | while read -r asn; do
        [[ -n "$asn" ]] && whois -h whois.radb.net -- "-i origin ${asn}" | tee \
            >(grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]+' | sort -u >>"${output_dir}/cidrs/asn_cidrs.txt")
    done

    # Using same steps for another scopes Wilde & Urls Scans

    run_wilde_mode "$target" "$subdomain_wordlist" "$output_dir"

    echo -e "\n\n-----------------------------------------------------------------\n\n"

    run_urls_mode "$target" "$subdomain_wordlist" "$vhost_wordlist" "$output_dir"

    echo -e "\n\n-----------------------------------------------------------------\n\n"
}

# Urls Mode Recon
run_urls_mode() {
    local target=$1
    local subdomain_wordlist=$2
    local vhost_wordlist=$3
    local output_dir=$4
    echo -e "\n\n-----------------------------------------------------------------\n\n"
    print_colored "3 - Now you are using Urls Mode (Focus: URL and JS Enumeration)" "$YELLOW"

    print_colored "Step 16: Claim URLs" "$BLUE"
    #   run_command katana "${output_dir}/urls/urls_katana.txt" true katana -xhr-extraction -form-extraction -js-crawl -list "${output_dir}/subdomains/unique_subdomains.txt" -o "${output_dir}/urls_katana.txt"
    # katana -u subdomains_alive.txt -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -kf -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -o allurls.txt
    # echo example.com | katana -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -f qurl | urldedupe >output.txt
    #   run_command gospider "${output_dir}/urls/urls_gospider.txt" true gospider -s "https://${target}/" -o "${output_dir}/urls_gospider.txt" -c 10 -d 1
    run_command gau "${output_dir}/urls/urls_gau.txt" true echo "${target}" | gau --subs --o "${output_dir}/urls/urls_gau.txt"
    #   run_command waybackurls "${output_dir}/urls/urls_waybackurls.txt" true echo "${target}" | waybackurls >> "${output_dir}/urls_waybackurls.txt"
    #   run_command hakrawler "${output_dir}/urls/urls_hakrawler.txt" true echo "https://${target}" | hakrawler -o "${output_dir}/urls_hakrawler.txt"

    #   print_colored "Step 17: Scan JS Files" "$BLUE"
    #   if [[ -f js-urls.txt ]]; then
    #       run_command hakcheckurl "${output_dir}/js_hakcheckurl.txt" true cat js-urls.txt | hakcheckurl -o "${output_dir}/urls/js_hakcheckurl.txt"
    #   else
    #       if [[ $count_only -ne 1 ]]; then
    #           print_colored "  [-] js-urls.txt not found" "$RED"
    #       fi
    #   fi

    #   if [[ -f js-files.txt ]]; then
    #       run_command python3 "${output_dir}/urls/js_dumpsterdiver.txt" true python3 DumpsterDiver.py -p js-files.txt -o "${output_dir}/js_dumpsterdiver.txt"
    #   else
    #       if [[ $count_only -ne 1 ]]; then
    #           print_colored "  [-] js-files.txt not found" "$RED"
    #       fi
    #   fi
    echo "now i grep js endpoints from '${output_dir}/urls' "

    cat "${output_dir}/urls"/* | grep -Eho 'https?://[^"]+\.js' >>"${output_dir}/urls/js_files.txt"
    run_command bash "${output_dir}/urls/js_linkfinder_results.html" true bash -c 'while read -r js_link; do linkfinder.py -i "$js_link" -o cli; done < "$0/urls/js_files.txt" > "$0/urls/js_linkfinder_results.html"' "$output_dir"

    #    print_colored "Step 18: Hidden Parameters" "$BLUE"
    #    run_command ffuf "${output_dir}/params/params_ffuf.txt" true ffuf -w "${subdomain_wordlist}" -u "https://${target}/script.php?FUZZ=test_value" -fs 4242 -o "${output_dir}/params_ffuf.txt"
    #    run_command arjun "${output_dir}/params/params_arjun.txt" true arjun -u "https://${target}/endpoint" -o "${output_dir}/params_arjun.txt"
    run_command python3 "${output_dir}/params/params_paramspider.txt" true python3 paramspider.py -d "${target}" -o "${output_dir}/params_paramspider.txt"

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

Main Recon Function
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
        mapfile -t targets <"$target_file"
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
        -h | --help)
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
        -d | --domain)
            domain=$2
            shift 2
            ;;
        -t | --target-file)
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
        -s | --subdomain-wordlist)
            subdomain_wordlist=$2
            shift 2
            ;;
        -v | --vhost-wordlist)
            vhost_wordlist=$2
            shift 2
            ;;
        -c | --count-only)
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
