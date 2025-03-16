#!/usr/bin/env python3

import argparse
import subprocess
import sys
from colorama import init, Fore, Style
import random
import os

# Initialize colorama for colored output
init()

# Custom print function with random colors
def print_colored(text, color=None):
    colors = [Fore.GREEN, Fore.BLUE, Fore.YELLOW, Fore.MAGENTA, Fore.CYAN]
    if color:
        print(f"{color}{text}{Style.RESET_ALL}")
    else:
        print(f"{random.choice(colors)}{text}{Style.RESET_ALL}")

# Function to run a shell command and display output
def run_command(command, display=True):
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    output, error = process.communicate()
    if process.returncode == 0 and display:
        for line in output.splitlines():
            print_colored(f"  [+] {line}")
        return output.strip()
    elif error and display:
        print_colored(f"  [-] Error: {error}", Fore.RED)
    return output.strip()

# Wilde Mode Recon
def run_wilde_mode(target, subdomain_wordlist, vhost_wordlist):
    print_colored("Now you are using Wilde Mode (Focus: IPs, ASNs, CIDRs, Subdomain Brute Forcing)", Fore.YELLOW)
    
    # Step 4: Reverse DNS Resolve Domains to IPs
    print_colored("Step 4: Reverse DNS Resolve Domains to IPs", Fore.BLUE)
    vt_api_key = "9c716df385ecb1665b0d8cf127da4fe9156564d22872d3109ef2e14a919286d8"
    run_command(f'curl -s "https://www.virustotal.com/vtapi/v2/domain/report?apikey={vt_api_key}&domain={target}" | jq -r ".. | .ip_address? // empty"')
    run_command(f'echo "{target}" | zdns A 2>/dev/null | jq -r \'.results.A.data.answers[] | select(.type == "A") | .answer\'')
    run_command(f'for url in $(echo {target}); do host $url | grep "has address" | cut -d " " -f 4 ;done')
    run_command(f'dig -x 8.8.8.8 +short')  # Example IP, replace with actual logic
    run_command(f'curl -s "https://api.hackertarget.com/reverseiplookup/?q=mx0b-004a6501.pphosted.com"')

    # Step 5: Claim ASN Number
    print_colored("Step 5: Claim ASN Number", Fore.BLUE)
    run_command(f'curl -s "https://bgp.tools/search?q={target}" --user-agent "fire-fox" | grep -Eo "([0-9]{{1,3}}\.){{3}}[0-9]{{1,3}}/[0-9]+" | sort -u')
    run_command(f'theHarvester -d {target} -b all')
    run_command(f'amass enum -active -d {target}')
    run_command(f'amass intel -asn 12345')  # Example ASN, replace with actual logic

    # Step 6: Convert ASN to CIDRs
    print_colored("Step 6: Convert ASN to CIDRs", Fore.BLUE)
    run_command(f'whois -h whois.radb.net -- "-i origin AS16509" | grep -Eo "([0-9.]+){{4}}/[0-9]+" | uniq')

    # Step 10: Subdomain Brute Forcing
    print_colored("Step 10: Subdomain Brute Forcing", Fore.BLUE)
    patterns = [f"adminFUZZ.{target}", f"FUZZadmin.{target}", f"admin-FUZZ.{target}", f"FUZZ-admin.{target}", f"admin.FUZZ.{target}"]
    for pattern in patterns:
        run_command(f"ffuf -w {subdomain_wordlist} -u 'https://{pattern}' -c -t 350 -mc all -fs 0")
    run_command(f"shuffledns -d {target} -w {subdomain_wordlist} -r resolvers.txt")
    run_command(f"gobuster dns -d {target} -t 50 -w {subdomain_wordlist}")
    run_command(f"dnscan.py -d dev-*.{target}")

# Open Mode Recon
def run_open_mode(target, subdomain_wordlist, vhost_wordlist):
    print_colored("Now you are using Open Mode (Full Reconnaissance)", Fore.YELLOW)
    
    # Step 3: Virtual Host Fuzzing
    print_colored("Step 3: Virtual Host Fuzzing", Fore.BLUE)
    run_command(f"gobuster vhost -u https://{target} -t 50 -w {vhost_wordlist}")
    run_command(f"VHostScan -t {target}")
    run_command(f"amass intel -d {target} -whois")

    # Step 4: Reverse DNS Resolve Domains to IPs (Repeated from Wilde)
    print_colored("Step 4: Reverse DNS Resolve Domains to IPs", Fore.BLUE)
    vt_api_key = "9c716df385ecb1665b0d8cf127da4fe9156564d22872d3109ef2e14a919286d8"
    run_command(f'curl -s "https://www.virustotal.com/vtapi/v2/domain/report?apikey={vt_api_key}&domain={target}" | jq -r ".. | .ip_address? // empty"')
    run_command(f'echo "{target}" | zdns A 2>/dev/null | jq -r \'.results.A.data.answers[] | select(.type == "A") | .answer\'')
    run_command(f'for url in $(echo {target}); do host $url | grep "has address" | cut -d " " -f 4 ;done')
    run_command(f'dig -x 8.8.8.8 +short')
    run_command(f'curl -s "https://api.hackertarget.com/reverseiplookup/?q=mx0b-004a6501.pphosted.com"')

    # Step 5: Claim ASN Number
    print_colored("Step 5: Claim ASN Number", Fore.BLUE)
    run_command(f'curl -s "https://bgp.tools/search?q={target}" --user-agent "fire-fox" | grep -Eo "([0-9]{{1,3}}\.){{3}}[0-9]{{1,3}}/[0-9]+" | sort -u')
    run_command(f'theHarvester -d {target} -b all')
    run_command(f'amass enum -active -d {target}')
    run_command(f'amass intel -asn 12345')

    # Step 6: Convert ASN to CIDRs
    print_colored("Step 6: Convert ASN to CIDRs", Fore.BLUE)
    run_command(f'whois -h whois.radb.net -- "-i origin AS16509" | grep -Eo "([0-9.]+){{4}}/[0-9]+" | uniq')

    # Step 7: Convert CIDR to IPs
    print_colored("Step 7: Convert CIDR to IPs", Fore.BLUE)
    run_command(f"nmap -n -sn 13.35.121.0/24 | grep 'for' | cut -d ' ' -f 5")
    run_command(f"zmap -p 80 13.35.121.0/24")  # Assuming zmap installed

    # Step 8: Resolve IPs to Domains (Reverse IP)
    print_colored("Step 8: Resolve IPs to Domains", Fore.BLUE)
    run_command(f"python3 hosthunter.py target-ips.txt")
    run_command(f"nmap -iL ips.txt -sn | grep for | cut -d ' ' -f 5")
    run_command(f'curl -s "https://api.hackertarget.com/reverseiplookup/?q=8.8.8.8"')
    run_command(f"shodan search 'net:8.8.8.8'")
    run_command(f"censys search 'ip:8.8.8.8'")
    run_command(f'curl -H "APIKEY: YOUR_API_KEY" "https://api.securitytrails.com/v1/domain/{target}/subdomains"')

    # Step 9: Subdomain Enumeration
    print_colored("Step 9: Subdomain Enumeration", Fore.BLUE)
    run_command(f"subfinder -d {target} -all -o subfinder_results.txt")
    run_command(f"amass enum -brute -active -d {target} -o amass_output.txt")
    run_command(f'curl -s "https://crt.sh/?q=%25.{target}" | grep -oE "[\.a-zA-Z0-9-]+\.{target}" | sort -u')
    run_command(f"theHarvester -d {target} -b all")
    run_command(f"subenum -d {target}")
    run_command(f"findomain -d {target}")
    run_command(f"assetfinder --subs-only {target}")
    run_command(f"sublist3r -d {target} -o subdomains.txt")
    run_command(f"massdns -r resolvers.txt -t A -o S -w massdns_output.txt {target}.txt")
    run_command(f"shodan domain {target}")
    run_command(f'curl -s "https://www.virustotal.com/vtapi/v2/domain/report?apikey={vt_api_key}&domain={target}" | jq -r ".domain_siblings[]"')
    run_command(f"chaos -d {target} -o chaos.txt")
    run_command(f'curl -s "https://api.securitytrails.com/v1/domain/{target}/subdomains?apikey=YOUR_API_KEY"')
    run_command(f"spyse -t domain -q {target}")
    run_command(f"urlscan -d {target}")
    run_command(f"zoomeye search 'domain:{target}'")
    run_command(f"censys search 'parsed.names: {target}' --index certificates")
    run_command(f"dnsrecon -d {target} -t brt -D {subdomain_wordlist} -c dnsrecon_output.csv")
    run_command(f"knockpy {target}")
    run_command(f"frogy -d {target} -o frogy_output.txt")
    run_command(f"github-subdomains -d {target} -t GITHUB_TOKEN -o github_subs.txt")
    run_command(f"gitlab-subdomains -d {target} -t GITLAB_TOKEN -o gitlab_subs.txt")
    run_command(f"alterx -l domains.txt -o alterx_output.txt")
    run_command(f"python3 oneforall.py --target {target} run")
    run_command(f"domainCollector -d {target} -o domainCollector_output.txt")
    run_command(f"echo | openssl s_client -connect {target}:443 -servername {target} 2>/dev/null | openssl x509 -noout -subject -issuer -ext subjectAltName")

    # Step 10: Subdomain Brute Forcing
    print_colored("Step 10: Subdomain Brute Forcing", Fore.BLUE)
    run_command(f"shuffledns -d {target} -w {subdomain_wordlist} -r resolvers.txt")
    run_command(f"gobuster dns -d {target} -t 50 -w {subdomain_wordlist}")
    run_command(f"dnscan.py -d dev-*.{target}")

    # Step 11: Directory Busting
    print_colored("Step 11: Directory Busting", Fore.BLUE)
    run_command(f"python3 dirsearch.py -u https://{target} -e php,html,js")
    run_command(f"feroxbuster -u https://{target} -w {subdomain_wordlist}")
    run_command(f"ffuf -u https://{target}/FUZZ -w {subdomain_wordlist} -o ffuf_results.json")

    # Step 13: Test for Subdomain Takeover
    print_colored("Step 13: Test for Subdomain Takeover", Fore.BLUE)
    run_command(f"subzy run --targets subdomains.txt --concurrency 100 --hide_fails --verify_ssl")

    # Step 14: Live Subdomains
    print_colored("Step 14: Live Subdomains", Fore.BLUE)
    run_command(f"cat subs.txt | httprobe")
    run_command(f"cat domains.txt | httpx -sc -ip -server -title -wc")

    # Step 15: Port Scanning
    print_colored("Step 15: Port Scanning", Fore.BLUE)
    run_command(f"naabu -host {target} -p- -Pn -o portscan")
    run_command(f"nmap -sV -sC -sS {target}")

    # Step 20: S3 Bucket Enumeration
    print_colored("Step 20: S3 Bucket Enumeration", Fore.BLUE)
    run_command(f"s3scanner -l domains.txt")

    # Step 22: Nuclei
    print_colored("Step 22: Nuclei Scanning", Fore.BLUE)
    run_command(f"nuclei -l domains.txt -t ~/nuclei-templates/http/exposures/")

    # Step 23: Test for XSS, Open Redirect, etc.
    print_colored("Step 23: Test for Vulnerabilities", Fore.BLUE)
    run_command(f"go run main.go xss.txt")
    run_command(f"assetfinder http://{target} | httpx -threads 300 -follow-redirects -silent | rush -j200 'curl -m5 -s -I -H \"Origin: http://evil.com\" {{}} | [[ $(grep -c \"http://evil.com\") -gt 0 ]] && printf \"\\n\\033[0;32m[VUL TO CORS] \\033[0m{{}}\"' 2>/dev/null")

# Urls Mode Recon
def run_urls_mode(target, subdomain_wordlist, vhost_wordlist):
    print_colored("Now you are using Urls Mode (Focus: URL and JS Enumeration)", Fore.YELLOW)
    
    # Step 16: Claim URLs
    print_colored("Step 16: Claim URLs", Fore.BLUE)
    run_command(f"katana -u https://{target}")
    run_command(f"gospider -s 'https://{target}/' -o output -c 10 -d 1")
    run_command(f"echo {target} | gau -subs")
    run_command(f"echo {target} | waybackurls")
    run_command(f"echo https://{target} | hakrawler")

    # Step 17: Scan JS Files
    print_colored("Step 17: Scan JS Files", Fore.BLUE)
    run_command(f"cat js-urls.txt | hakcheckurl")
    run_command(f"python3 linkfinder.py -i https://{target}/script.js -o results.html")
    run_command(f"python3 DumpsterDiver.py -p js-files.txt")

    # Step 18: Hidden Parameters
    print_colored("Step 18: Hidden Parameters", Fore.BLUE)
    run_command(f"ffuf -w {subdomain_wordlist} -u https://{target}/script.php?FUZZ=test_value -fs 4242")
    run_command(f"arjun -u https://{target}/endpoint")
    run_command(f"python3 paramspider.py -d {target}")

# Main Recon Function
def run_recon(args):
    mode = "Unknown"
    targets = []

    if args.wilde:
        mode = "wilde"
    elif args.open:
        mode = "open"
    elif args.urls:
        mode = "urls"

    if args.domain:
        targets = [args.domain]
        print_colored(f"Target Domain: {args.domain}", Fore.GREEN)
    elif args.target_file:
        with open(args.target_file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
        print_colored(f"Targets from file: {args.target_file} ({len(targets)} lines)", Fore.GREEN)
    else:
        print_colored("Error: Please provide either -d or -t", Fore.RED)
        sys.exit(1)

    print_colored(f"Current Mode: {mode}", Fore.YELLOW)
    print_colored("Created By Ahmex000", Fore.GREEN + Style.DIM)

    for target in targets:
        if mode == "wilde":
            run_wilde_mode(target, args.subdomain_wordlist, args.vhost_wordlist)
        elif mode == "open":
            run_open_mode(target, args.subdomain_wordlist, args.vhost_wordlist)
        elif mode == "urls":
            run_urls_mode(target, args.subdomain_wordlist, args.vhost_wordlist)

# Argument Parsing
def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Y-Recon: A comprehensive reconnaissance automation tool",
        epilog="""
        Usage Examples:
          1. Single Domain, Wilde Mode (IP/ASN/Subdomain Focus):
             y-recon.py -d example.com -wilde -s /path/to/subdomains.txt -v /path/to/vhosts.txt
          2. File with Domains, Open Mode (Full Recon):
             y-recon.py -t targets.txt -open -s /path/to/subdomains.txt -v /path/to/vhosts.txt
          3. Single Domain, Urls Mode (URL/JS Focus):
             y-recon.py -d example.com -urls -s /path/to/subdomains.txt -v /path/to/vhosts.txt

        Mode Descriptions:
          -wilde: Focuses on IPs, ASNs, CIDRs, and subdomain brute forcing.
          -open: Performs full reconnaissance covering all steps from recon.txt.
          -urls: Focuses on URL enumeration and JS file scanning.
        """
    )
    group_target = parser.add_mutually_exclusive_group(required=True)
    group_target.add_argument("-d", "--domain", help="Single target domain (e.g., example.com)")
    group_target.add_argument("-t", "--target-file", help="File containing list of domains")

    group_mode = parser.add_mutually_exclusive_group(required=True)
    group_mode.add_argument("-wilde", action="store_true", help="Run in wilde mode (IP/ASN/subdomain focus)")
    group_mode.add_argument("-open", action="store_true", help="Run in open mode (full recon)")
    group_mode.add_argument("-urls", action="store_true", help="Run in urls mode (URL/JS focus)")

    parser.add_argument("-s", "--subdomain-wordlist", required=True, help="Path to subdomain wordlist (e.g., /path/to/subdomains.txt)")
    parser.add_argument("-v", "--vhost-wordlist", required=True, help="Path to vhost wordlist (e.g., /path/to/vhosts.txt)")

    return parser.parse_args()

# Main Execution
if __name__ == "__main__":
    args = parse_arguments()
    run_recon(args)
