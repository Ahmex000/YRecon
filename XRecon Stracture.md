# write XRecon with -/\| as any CLI tool with big or medium size

/* now all comming steps i need it with random and good color and styles */

# write with green and small font (Created By Ahmex000)
# write if i imported file or just domain , if file write me number if line's and if domain write me a domain name 
# wirte my current mode (open , wilde , urls)

/* the script must  have 5 argument's 
-d if i will give it one domain
-t file 
-wilde to do some commands (i will write him now)
-open to do all script steps
-urls to do all urls steps (i will write all steps now)

# now if i give the tool -d i will one domain (the script must have one of two argument's -d for one domain , -t for file containing list of domains)
# the tool must have one of following (-wild to do wild card recon steps - i will write it - , -open to do all script steps , -urls to do all urls procces and js)

(if i passed file , i need evey tool just have one file for all domains in file)

---






### -wild section

- echo now you using Wild Mode
(organize all steps with numbers)

- mkdir (targetname)
- cd (targetname) ; mkdir IPs ; cd IPs
- now Reverse DNS Resolve Domain/s to IP/s with this commands
- #echo getting ip with virus total
- curl -s "https://www.virustotal.com/vtapi/v2/domain/report?apikey=9c716df385ecb1665b0d8cf127da4fe9156564d22872d3109ef2e14a919286d8&domain=unisys.com" | jq -r '.. | .ip_address? // empty'
 and add it in virus total file and add line of '--' becouse we will add another IP's// empty'
- echo "unisys.com" | zdns A 2>/dev/null | jq -r '.results.A.data.answers[] | select(.type == "A") | .answer' and add it in IP's file also , but check if th ips file have this ips , here dont add it
- curl -s "https://api.hackertarget.com/reverseiplookup/?q=mx0b-004a6501.pphosted.com" in subdomains folder/subdomains file
- curl -s "https://bgp.tools/search?q=dell" --user-agent "fire-fox" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]+' | sort -u / and take ASN's to ASNSfloder/asnsfile , and take CIDRs to CIDRs file 
 (the response contain both CIDRs and ASNS) 
- ffuf -w /subdomain_megalist.txt -u 'https://adminFUZZ.Target.com' -c  -t 350 -mc all  -fs 0 //brute force subdomains
```
admin-FUZZ.target.com E.G: admin-stg.target.com
FUZZ-admin.target.com E.G: cert-admin.target.com
adminFUZZ.target.com  E.G: admintest.target.com
FUZZadmin.target.com  E.G  testadmin.target.com
admin.FUZZ.target.com E.G: admin.dev.target.com
```


---







### -open section
- echo now you using Open Mode

- curl -s "https://crt.sh/?O={organization name}&output=json" | jq -r ".[].common_name" | tr A-Z a-z | unfurl format %r.%t | sort -u / take ips in ips file and domains also as normal
- echo search for TLD's to another TLD
- echo "Virtual Host Fuzzing"
- gobuster vhost -u https://Domain.com -t 50 -w subdomains.txt -o / and add valid output in doamins file




---







### -urls section
- echo now you using Urls Mode
-  

