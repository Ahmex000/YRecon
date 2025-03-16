#!/usr/bin/env python3

import argparse
import os
import subprocess
import sys
from datetime import datetime
import shutil
from colorama import init, Fore, Style
import random

# Initialize colorama for cross-platform colored output
init()

# Custom print function with random colors for steps
def print_colored(text, color=None):
    colors = [Fore.GREEN, Fore.BLUE, Fore.YELLOW, Fore.MAGENTA, Fore.CYAN]
    if color:
        print(f"{color}{text}{Style.RESET_ALL}")
    else:
        print(f"{random.choice(colors)}{text}{Style.RESET_ALL}")

# Function to create directories and organize output
def setup_directory_structure(target):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_dir = f"{target}_{timestamp}"
    os.makedirs(base_dir, exist_ok=True)
    return base_dir

# Function to append to a file and display output in real-time
def append_to_file_and_display(filename, content, display=True):
    with open(filename, 'a') as f:
        f.write(content + '\n')
    if display:
        print_colored(f"  [+] {content}")

# Function to run a shell command and capture output
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

# Function to deduplicate a file
def deduplicate_file(filename):
    with open(filename, 'r') as f:
        lines = set(f.read().splitlines())
    with open(filename, 'w') as f:
        f.write('\n'.join(sorted(lines)))

# Main recon function
def run_recon(args):
    mode = "Unknown"
    targets = []

    # Determine mode and targets
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

    # Process each target
    for target in targets:
        base_dir = setup_directory_structure(target)
        print_colored(f"Working in directory: {base_dir}", Fore.CYAN)

        if mode == "wilde":
            run_wilde_mode(target, base_dir)
        elif mode == "open":
            run_open_mode(target, base_dir)
        elif mode == "urls":
            run_urls_mode(target, base_dir)

        # Combine and deduplicate subdomains if they exist
        subdomain_files = [os.path.join(base_dir, f) for f in os.listdir(base_dir) if "subdomains" in f]
        if subdomain_files:
            combined_subdomains = os.path.join(base_dir, "all_subdomains.txt")
            with open(combined_subdomains, 'w') as outfile:
                for fname in subdomain_files:
                    with open(fname, 'r') as infile:
                        outfile.write(infile.read())
            deduplicate_file(combined_subdomains)
            print_colored(f"Combined and deduplicated subdomains saved to: {combined_subdomains}", Fore.GREEN)

            # Check live subdomains
            live_subdomains = os.path.join(base_dir, "live_subdomains.txt")
            run_command(f"cat {combined_subdomains} | httpx -silent > {live_subdomains}")
            print_colored(f"Live subdomains saved to: {live_subdomains}", Fore.GREEN)

# Wilde Mode
def run_wilde_mode(target, base_dir):
    print_colored("Now you are using Wilde Mode", Fore.YELLOW)
    
    # Step 1: Create IPs directory
    print_colored("1. Setting up IPs directory", Fore.BLUE)
    ips_dir = os.path.join(base_dir, "IPs")
    os.makedirs(ips_dir, exist_ok=True)
    ips_file = os.path.join(ips_dir, "ips.txt")
    subdomains_dir = os.path.join(base_dir, "subdomains")
    os.makedirs(subdomains_dir, exist_ok=True)
    subdomains_file = os.path.join(subdomains_dir, "subdomains.txt")
    asns_dir = os.path.join(base_dir, "ASNs")
    os.makedirs(asns_dir, exist_ok=True)
    asns_file = os.path.join(asns_dir, "asns.txt")
    cidrs_file = os.path.join(asns_dir, "cidrs.txt")

    # Step 2: Reverse DNS Resolve Domains to IPs
    print_colored("2. Reverse DNS Resolve Domains to IPs", Fore.BLUE)
    print_colored("  Getting IPs with VirusTotal", Fore.CYAN)
    vt_api_key = "9c716df385ecb1665b0d8cf127da4fe9156564d22872d3109ef2e14a919286d8"
    vt_output = run_command(f'curl -s "https://www.virustotal.com/vtapi/v2/domain/report?apikey={vt_api_key}&domain={target}" | jq -r ".. | .ip_address? // empty"')
    if vt_output:
        append_to_file_and_display(ips_file, vt_output)
        append_to_file_and_display(ips_file, "--")

    print_colored("  Getting IPs with zdns", Fore.CYAN)
    zdns_output = run_command(f'echo "{target}" | zdns A 2>/dev/null | jq -r \'.results.A.data.answers[] | select(.type == "A") | .answer\'')
    if zdns_output:
        with open(ips_file, 'r') as f:
            existing_ips = set(f.read().splitlines())
        for ip in zdns_output.splitlines():
            if ip not in existing_ips:
                append_to_file_and_display(ips_file, ip)

    print_colored("  Reverse IP lookup with hackertarget", Fore.CYAN)
    hackertarget_output = run_command(f'curl -s "https://api.hackertarget.com/reverseiplookup/?q=mx0b-004a6501.pphosted.com"')
    if hackertarget_output:
        append_to_file_and_display(subdomains_file, hackertarget_output)

    # Step 3: BGP Tools for ASNs and CIDRs
    print_colored("3. Fetching ASNs and CIDRs with bgp.tools", Fore.BLUE)
    bgp_output = run_command(f'curl -s "https://bgp.tools/search?q={target}" --user-agent "fire-fox" | grep -Eo "([0-9]{{1,3}}\.){{3}}[0-9]{{1,3}}/[0-9]+" | sort -u')
    if bgp_output:
        for line in bgp_output.splitlines():
            if "/" in line:
                append_to_file_and_display(cidrs_file, line)
            else:
                append_to_file_and_display(asns_file, line)

    # Step 4: Virtual Host Fuzzing with ffuf
    print_colored("4. Brute forcing subdomains with ffuf", Fore.BLUE)
    subdomain_list = "/path/to/subdomain_megalist.txt"  # Replace with your actual path
    patterns = [
        f"adminFUZZ.{target}",
        f"FUZZadmin.{target}",
        f"admin-FUZZ.{target}",
        f"FUZZ-admin.{target}",
        f"admin.{FUZZ}.{target}"
    ]
    for pattern in patterns:
        ffuf_output = run_command(f"ffuf -w {subdomain_list} -u 'https://{pattern}' -c -t 350 -mc all -fs 0")
        if ffuf_output:
            append_to_file_and_display(subdomains_file, ffuf_output)

# Open Mode
def run_open_mode(target, base_dir):
    print_colored("Now you are using Open Mode", Fore.YELLOW)
    
    ips_file = os.path.join(base_dir, "ips.txt")
    domains_file = os.path.join(base_dir, "domains.txt")

    # Step 1: crt.sh for domains and IPs
    print_colored("1. Fetching from crt.sh", Fore.BLUE)
    org_name = target.split('.')[0]  # Simplistic assumption, adjust as needed
    crt_output = run_command(f'curl -s "https://crt.sh/?O={org_name}&output=json" | jq -r ".[].common_name" | tr A-Z a-z | unfurl format %r.%t | sort -u')
    if crt_output:
        for line in crt_output.splitlines():
            if line.endswith(f".{target}"):
                append_to_file_and_display(domains_file, line)
            else:
                append_to_file_and_display(ips_file, line)

    # Step 2: TLD Search
    print_colored("2. Searching for TLDs", Fore.BLUE)
    print_colored("  (Implement TLD search logic here)", Fore.CYAN)

    # Step 3: Virtual Host Fuzzing
    print_colored("3. Virtual Host Fuzzing with gobuster", Fore.BLUE)
    gobuster_output = run_command(f"gobuster vhost -u https://{target} -t 50 -w /path/to/subdomains.txt -o -")
    if gobuster_output:
        append_to_file_and_display(domains_file, gobuster_output)

# Urls Mode
def run_urls_mode(target, base_dir):
    print_colored("Now you are using Urls Mode", Fore.YELLOW)
    # Add URL-related steps here as per your document
    print_colored("  (URL steps to be implemented)", Fore.CYAN)

# Argument parsing
def parse_arguments():
    parser = argparse.ArgumentParser(description="Y-Recon: A reconnaissance automation tool")
    group_target = parser.add_mutually_exclusive_group(required=True)
    group_target.add_argument("-d", "--domain", help="Single target domain")
    group_target.add_argument("-t", "--target-file", help="File containing list of domains")
    
    group_mode = parser.add_mutually_exclusive_group(required=True)
    group_mode.add_argument("-wilde", action="store_true", help="Run in wilde mode")
    group_mode.add_argument("-open", action="store_true", help="Run in open mode")
    group_mode.add_argument("-urls", action="store_true", help="Run in urls mode")
    
    return parser.parse_args()

# Main execution
if __name__ == "__main__":
    args = parse_arguments()
    run_recon(args)
