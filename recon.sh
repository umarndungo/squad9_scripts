#!/bin/bash

# Check if domain is supplied
if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    echo "Example: $0 example.com"
    exit 1
fi

DOMAIN="$1"
OUTPUT_DIR="recon_${DOMAIN}"
LIVE_STATUS_CODES="200,403"
NUCLEI_TAGS="exposures,secrets"
# Nmap scan profile (adjust as needed)
NMAP_PORTS="80,443,8080,8443,3000,5000,7000,8000"  # common web ports
NMAP_FLAGS="-sV -sS -sC --open -T4 -Pn"

# Create output directory
mkdir -p "$OUTPUT_DIR"
cd "$OUTPUT_DIR" || exit 1

echo "[+] Starting reconnaissance on $DOMAIN"
echo "[+] Results will be saved in $OUTPUT_DIR"
echo "========================================="

# WHOIS lookup
echo "[+] Running whois..."
whois "$DOMAIN" > "whois.txt"

# NSLookup
echo "[+] Running nslookup..."
nslookup "$DOMAIN" > "nslookup.txt"

# Subfinder and amass with httpx and katana
echo "[+] Running subfinder with httpx and katana..."
subfinder -all -d "$DOMAIN" -silent -o subfinder_domains.txt
amass enum -passive -d "$DOMAIN" -o amass_domains.txt

# Combine and sort subdomains
cat "subfinder_domains.txt" "amass_domains.txt" \
    | sort -u > "all_subdomains.txt"
sub_count=$(wc -l < "all_subdomains.txt")
echo "Total unique subdomains found: $sub_count"

# Filter  live subdomains
echo "Step 2: Filtering live subdomains with httpx..."
httpx -l "all_subdomains.txt" -silent \
    -status-code -mc "$LIVE_STATUS_CODES" \
    -o "live_domains.txt"
live_count=$(wc -l < "live_domains.txt")
echo "Identified $live_count live domains."

if [ "$live_count" -eq 0 ]; then
    echo "No live domains found. Exiting."
    exit 0
fi

# Nmap scan
echo "[+] Running nmap..."
# nmap -sV -sS -sC -T4 --open "$DOMAIN" > "nmap.txt"
while IFS= read -r domain; do
    echo "  Scanning $domain..."
    $NMAP $NMAP_FLAGS -p "$NMAP_PORTS" "$DOMAIN" > "nmap_${DOMAIN//[^a-zA-Z0-9]/_}.txt" 2>/dev/null || \
        echo "  nmap scan failed for $DOMAIN"
done < "live_domains.txt"

# WhatWeb
echo "[+] Running whatweb..."
# whatweb "https://$DOMAIN" > "whatweb.txt"
while IFS= read -r domain; do
    echo "  Analyzing $DOMAIN..."
    whatweb --no-errors --color=never "$DOMAIN" >> "whatweb.txt" 2>/dev/null || \
        echo "  whatweb failed for $DOMAIN"
done < "live_domains.txt"

# WAFW00F
echo "[+] Running wafw00f..."
#wafw00f -a -l "$DOMAIN" > "wafw00f.txt"
while IFS= read -r domain; do
    echo "Testing $DOMAIN..."
    wafwoof "$DOMAIN" >> "wafw00f.txt" 2>/dev/null || \
        echo "wafw00f failed for $DOMAIN"
done < "live_domains.txt"

# WPScan (if WordPress is detected)
echo "[+] Running wpscan..."
#wpscan --random-user-agent --url "https://$DOMAIN" > "wpscan.txt" 2>&1
grep -i "WordPress" "whatweb.txt" | cut -d' ' -f1 | sort -u > "wordpress_domains.txt" 2>/dev/null || true
if [ -s "wordpress_domains.txt" ]; then
    echo "WordPress detected on $(wc -l < "wordpress_domains.txt") domains. Running wpscan..."
    while IFS= read -r domain; do
        echo "  Scanning $DOMAIN with wpscan..."
        wpscan --url "http://$DOMAIN" --no-update --enumerate --disable-tls-checks \
            -o "wpscan_${DOMAIN//[^a-zA-Z0-9]/_}.txt" 2>/dev/null || \
            echo "  wpscan failed for $DOMAIN"
        # Also try HTTPS if it exists
        if [ -f "nmap_${DOMAIN//[^a-zA-Z0-9]/_}.txt" ] && grep -q "443/open" "nmap_${DOMAIN//[^a-zA-Z0-9]/_}.txt"; then
            wpscan --url "https://$DOMAIN" --no-update --enumerate --disable-tls-checks \
                -o "wpscan_https_${DOMAIN//[^a-zA-Z0-9]/_}.txt" 2>/dev/null || true
        fi
    done < "wordpress_domains.txt"
else
    echo "No WordPress installations detected."
fi

# ----- Step 5: Collect URLs from multiple sources -----------------
echo "Step 5a: Crawling live domains with Katana..."
katana -list "live_domains.txt" -silent \
    -o "katana_urls.txt" \
    -jc -fx -d 3

echo "Fetching historical URLs with waybackurls..."
while IFS= read -r domain; do
    echo "$DOMAIN" | waybackurls >> "wayback_urls.txt"
done < "live_domains.txt"

echo "Fetching historical URLs with gau..."
while IFS= read -r domain; do
    gau "$DOMAIN" >> "gau_urls.txt"
done < "live_domains.txt"

# Combine all URLs, deduplicate
cat "katana_urls.txt" \
    "wayback_urls.txt" \
    "gau_urls.txt" 2>/dev/null \
    | sort -u > "all_urls.txt"
url_count=$(wc -l < "all_urls.txt")
echo "Total unique URLs collected: $url_count"

# ----- Step 6: Extract JavaScript files ---------------------------
echo "Extracting JavaScript files..."
grep -i "\.js" "all_urls.txt" | sort -u > "js_files.txt"
js_count=$(wc -l < "js_files.txt")
echo "Found $js_count JavaScript files."

if [ "$js_count" -eq 0 ]; then
    echo "No JavaScript files found. Exiting."
    exit 0
fi

# ----- Step 7: Scan JS files with Nuclei --------------------------
echo "Scanning JS files with Nuclei (tags: $NUCLEI_TAGS)..."
nuclei -l "js_files.txt" -silent \
    -tags "$NUCLEI_TAGS" \
    -o "nuclei_findings.txt"

findings_count=$(wc -l < "nuclei_findings.txt")
echo "Pipeline finished. Found $findings_count potential secret exposures."
if [ "$findings_count" -gt 0 ]; then
    echo "Check nuclei_findings.txt for details."
else
    echo "No secrets detected using the selected Nuclei templates."
fi

# Gobuster directory enumeration
#echo "[+] Running gobuster..."
#gobuster dir -u "https://$DOMAIN" -w /usr/share/wordlists/dirb/common.txt --no-error > "gobuster.txt"

# Collect URLS from multiple sources
#echo "Step 5a: Crawling live domains with Katana..."
#katana -list "live_domains.txt" -silent \
#    -o "katana_urls.txt" \
#    -jc -fx -d 3

echo "========================================="
echo "[+] Reconnaissance completed!"
echo "[+] Results saved in $OUTPUT_DIR"
echo "[+] Files created:"
ls -la