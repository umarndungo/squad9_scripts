#!/bin/bash
# enhanced_recon_secrets.sh – Multi‑tool passive recon + secrets discovery
# Usage: ./enhanced_recon_secrets.sh target.com [output_directory]

set -euo pipefail

# --- Configuration -------------------------------------------------
TARGET="${1:-}"
OUTPUT_DIR="${2:-recon_${TARGET//[^a-zA-Z0-9]/_}}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="${OUTPUT_DIR}/pipeline_${TIMESTAMP}.log"

# Tool paths (adjust if needed)
SUBFINDER="subfinder"
AMASS="amass"
HTTPX="httpx"
KATANA="katana"
WAYBACKURLS="waybackurls"
GAU="gau"
NUCLEI="nuclei"
NMAP="nmap"
WAFW00F="wafw00f"
WHOIS="whois"
NSLOOKUP="nslookup"
WPSCAN="wpscan"
WHATWEB="whatweb"

# Filters
LIVE_STATUS_CODES="200,403"
NUCLEI_TAGS="exposures,secrets"

# Nmap scan profile (adjust as needed)
NMAP_PORTS="80,443,8080,8443,3000,5000,7000,8000"  # common web ports
NMAP_FLAGS="-sV -sS -sC --open -T4 -Pn"

# --- Functions -----------------------------------------------------
log() {
    echo -e "[$(date +'%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

usage() {
    cat <<EOF
Usage: $0 <target_domain> [output_directory]

Example: $0 example.com ./my_recon

This script performs a comprehensive recon workflow:
  1. Subdomain enumeration: Subfinder + Amass
  2. Live domain filtering: httpx
  3. Basic reconnaissance: whois, nslookup, nmap, whatweb, wafw00f
  4. WordPress scanning: wpscan (if WordPress detected)
  5. URL crawling: Katana
  6. Historical URL gathering: waybackurls + gau
  7. JavaScript file extraction
  8. Secrets scanning: Nuclei (exposures & secrets templates)

All results are stored in the output directory (default: recon_<target>).
EOF
    exit 0
}

check_tools() {
    local missing=()
    for tool in "$SUBFINDER" "$AMASS" "$HTTPX" "$KATANA" "$WAYBACKURLS" "$GAU" "$NUCLEI" \
                "$NMAP" "$WAFW00F" "$WHOIS" "$NSLOOKUP" "$WPSCAN" "$WHATWEB"; do
        if ! command -v "$tool" &>/dev/null; then
            missing+=("$tool")
        fi
    done
    if [ ${#missing[@]} -gt 0 ]; then
        log "ERROR: Missing tools: ${missing[*]}"
        log "Please install missing tools:"
        log "  - Subfinder:  https://github.com/projectdiscovery/subfinder"
        log "  - Amass:      https://github.com/OWASP/Amass"
        log "  - httpx:      https://github.com/projectdiscovery/httpx"
        log "  - Katana:     https://github.com/projectdiscovery/katana"
        log "  - waybackurls: https://github.com/tomnomnom/waybackurls"
        log "  - gau:        https://github.com/lc/gau"
        log "  - Nuclei:     https://github.com/projectdiscovery/nuclei"
        log "  - nmap:       https://nmap.org/"
        log "  - wafw00f:    https://github.com/EnableSecurity/wafw00f"
        log "  - whois:      install via your package manager"
        log "  - nslookup:   part of bind-utils or dnsutils"
        log "  - wpscan:     https://github.com/wpscanteam/wpscan"
        log "  - whatweb:    https://github.com/urbanadventurer/WhatWeb"
        exit 1
    fi
    log "All required tools are available."
}

# --- Main ----------------------------------------------------------
if [ -z "$TARGET" ]; then
    usage
fi

mkdir -p "$OUTPUT_DIR"
echo "$OUTPUT_DIR" >> ".gitignore"
log "Starting enhanced reconnaissance for $TARGET"
log "Output will be stored in $OUTPUT_DIR"

# ----- Step 1: Subdomain enumeration (Subfinder + Amass) ----------
log "Step 1a: Running Subfinder..."
touch "${OUTPUT_DIR}/subfinder_domains.txt"
subfinder -d "$TARGET" -silent -o "${OUTPUT_DIR}/subfinder_domains.txt"

log "Step 1b: Running Amass (passive mode)..."
touch "${OUTPUT_DIR}/amass_domains.txt"
amass enum -passive -d "$TARGET" -o "${OUTPUT_DIR}/amass_domains.txt"

# Combine and deduplicate subdomains
cat "${OUTPUT_DIR}/subfinder_domains.txt" "${OUTPUT_DIR}/amass_domains.txt" \
    | sort -u > "${OUTPUT_DIR}/all_subdomains.txt"
sub_count=$(wc -l < "${OUTPUT_DIR}/all_subdomains.txt")
log "Total unique subdomains found: $sub_count"

# ----- Step 2: Filter live subdomains -----------------------------
log "Step 2: Filtering live subdomains with httpx..."
# Uncomment this below and comment out the custom path below it:
httpxgo="$HOME/go/bin/httpx"
# httpxgo="/home/chiefomar/go/bin/httpx"
$httpxgo -list "${OUTPUT_DIR}/all_subdomains.txt" -silent \
    -status-code -mc "$LIVE_STATUS_CODES" \
    -o "${OUTPUT_DIR}/live_domains.txt"
live_count=$(wc -l < "${OUTPUT_DIR}/live_domains.txt")
log "Identified $live_count live domains."

if [ "$live_count" -eq 0 ]; then
    log "No live domains found. Exiting."
    exit 0
fi

# ----- Step 3: Basic Recon (whois, nslookup, nmap, whatweb, wafw00f) ----
log "Step 3a: Running whois on target domain..."
$WHOIS "$TARGET" > "${OUTPUT_DIR}/whois.txt" 2>/dev/null || log "whois failed for $TARGET"

log "Step 3b: Running nslookup on target domain..."
$NSLOOKUP "$TARGET" > "${OUTPUT_DIR}/nslookup.txt" 2>/dev/null || log "nslookup failed for $TARGET"

log "Step 3c: Scanning live domains with nmap (ports: $NMAP_PORTS)..."
# For each live domain, run nmap and store output
while IFS= read -r domain; do
    log "  Scanning $domain..."
    $NMAP $NMAP_FLAGS -p "$NMAP_PORTS" "$domain" > "${OUTPUT_DIR}/nmap_${domain//[^a-zA-Z0-9]/_}.txt" 2>/dev/null || \
        log "  nmap scan failed for $domain"
done < "${OUTPUT_DIR}/live_domains.txt"

log "Step 3d: Fingerprinting web technologies with whatweb..."
touch "${OUTPUT_DIR}/whatweb.txt"
while IFS= read -r domain; do
    log "  Analyzing $domain..."
    $WHATWEB --no-errors --color=never "$domain" >> "${OUTPUT_DIR}/whatweb.txt" 2>/dev/null || \
        log "  whatweb failed for $domain"
done < "${OUTPUT_DIR}/live_domains.txt"

log "Step 3e: Detecting WAFs with wafw00f..."
touch "${OUTPUT_DIR}/wafw00f.txt"
while IFS= read -r domain; do
    log "  Testing $domain..."
    $WAFW00F -a -l "$domain" | tee -a "${OUTPUT_DIR}/wafw00f.txt" 2>/dev/null || \
        log "  wafw00f failed for $domain"
done < "${OUTPUT_DIR}/live_domains.txt"

log "Step 3f: directory discovery with gobuster..."
touch "gobuster.txt"
gobuster dir -u "https:$domain" -w /usr/share/wordlists/dirb/common.txt --no-error -b 301 | tee -a gobuster.txt

# ----- Step 4: WordPress scanning (if WordPress detected) ----------
log "Step 4: Checking for WordPress installations..."
touch "${OUTPUT_DIR}/wordpress_domains.txt"
# If whatweb output contains "WordPress", run wpscan on those domains
grep -i "WordPress" "${OUTPUT_DIR}/whatweb.txt" | cut -d' ' -f1 | sort -u > "${OUTPUT_DIR}/wordpress_domains.txt" 2>/dev/null || true
if [ -s "${OUTPUT_DIR}/wordpress_domains.txt" ]; then
    log "WordPress detected on $(wc -l < "${OUTPUT_DIR}/wordpress_domains.txt") domains. Running wpscan..."
    while IFS= read -r domain; do
        log "  Scanning $domain with wpscan..."
        $WPSCAN --random-user-agent --url "http://$domain" --no-update --enumerate --disable-tls-checks \
            -o "${OUTPUT_DIR}/wpscan_${domain//[^a-zA-Z0-9]/_}.txt" 2>/dev/null || \
            log "  wpscan failed for $domain"
        # Also try HTTPS if it exists
        if [ -f "${OUTPUT_DIR}/nmap_${domain//[^a-zA-Z0-9]/_}.txt" ] && grep -q "443/open" "${OUTPUT_DIR}/nmap_${domain//[^a-zA-Z0-9]/_}.txt"; then
            $WPSCAN --random-user-agent --url "https://$domain" --no-update --enumerate --disable-tls-checks \
                -o "${OUTPUT_DIR}/wpscan_https_${domain//[^a-zA-Z0-9]/_}.txt" 2>/dev/null || true
        fi
    done < "${OUTPUT_DIR}/wordpress_domains.txt"
else
    log "No WordPress installations detected."
fi

# ----- Step 5: Collect URLs from multiple sources -----------------
log "Step 5a: Crawling live domains with Katana..."
touch "${OUTPUT_DIR}/katana_urls.txt"
$KATANA -list "${OUTPUT_DIR}/live_domains.txt" -silent \
    -o "${OUTPUT_DIR}/katana_urls.txt" \
    -jc -fx -d 3

log "Step 5b: Fetching historical URLs with waybackurls..."
touch "${OUTPUT_DIR}/wayback_urls.txt"
while IFS= read -r domain; do
    echo "$domain" | $WAYBACKURLS >> "${OUTPUT_DIR}/wayback_urls.txt"
done < "${OUTPUT_DIR}/live_domains.txt"

log "Step 5c: Fetching historical URLs with gau..."
touch "${OUTPUT_DIR}/gau_urls.txt"
while IFS= read -r domain; do
    $GAU "$domain" >> "${OUTPUT_DIR}/gau_urls.txt"
done < "${OUTPUT_DIR}/live_domains.txt"

log "Step 5ci: Fetching historical URLs with getallurls..."
touch "${OUTPUT_DIR}/gau_urls.txt"
while IFS= read -r domain; do
    getallurls "$domain" >> "${OUTPUT_DIR}/gau_urls.txt"
done < "${OUTPUT_DIR}/live_domains.txt"


# Combine all URLs, deduplicate
cat "${OUTPUT_DIR}/katana_urls.txt" \
    "${OUTPUT_DIR}/all_subdomains.txt" \
    "${OUTPUT_DIR}/wayback_urls.txt" \
    "${OUTPUT_DIR}/gau_urls.txt" 2>/dev/null \
    | sort -u > "${OUTPUT_DIR}/all_urls.txt"
url_count=$(wc -l < "${OUTPUT_DIR}/all_urls.txt")
log "Total unique URLs collected: $url_count"

# ----- Step 6: Extract JavaScript files ---------------------------
log "Step 6: Extracting JavaScript files..."
grep -i "\.js" "${OUTPUT_DIR}/all_urls.txt" | sort -u > "${OUTPUT_DIR}/js_files.txt"
js_count=$(wc -l < "${OUTPUT_DIR}/js_files.txt")
log "Found $js_count JavaScript files."

if [ "$js_count" -eq 0 ]; then
    log "No JavaScript files found. Exiting."
    exit 0
fi

# ----- Step 7: Scan JS files with Nuclei --------------------------
log "Step 7: Scanning JS files with Nuclei (tags: $NUCLEI_TAGS)..."
touch "${OUTPUT_DIR}/nuclei_findings.txt"
$NUCLEI -l "${OUTPUT_DIR}/js_files.txt" -silent \
    -tags "$NUCLEI_TAGS" \
    -o "${OUTPUT_DIR}/nuclei_findings.txt"

findings_count=$(wc -l < "${OUTPUT_DIR}/nuclei_findings.txt")
log "Pipeline finished. Found $findings_count potential secret exposures."
if [ "$findings_count" -gt 0 ]; then
    log "Check ${OUTPUT_DIR}/nuclei_findings.txt for details."
else
    log "No secrets detected using the selected Nuclei templates."
fi

exit 0