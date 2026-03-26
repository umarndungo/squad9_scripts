#!/usr/bin/env bash
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

# Filters
LIVE_STATUS_CODES="200,403"
NUCLEI_TAGS="exposures,secrets"

# --- Functions -----------------------------------------------------
log() {
    echo -e "[$(date +'%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

usage() {
    cat <<EOF
Usage: $0 <target_domain> [output_directory]

Example: $0 example.com ./my_recon

This script performs a passive recon workflow:
  1. Subdomain enumeration: Subfinder + Amass
  2. Live domain filtering: httpx
  3. URL crawling: Katana
  4. Historical URL gathering: waybackurls + gau
  5. JavaScript file extraction
  6. Secrets scanning: Nuclei (exposures & secrets templates)

All results are stored in the output directory (default: recon_<target>).
EOF
    exit 0
}

check_tools() {
    local missing=()
    for tool in "$SUBFINDER" "$AMASS" "$HTTPX" "$KATANA" "$WAYBACKURLS" "$GAU" "$NUCLEI"; do
        if ! command -v "$tool" &>/dev/null; then
            missing+=("$tool")
        fi
    done
    if [ ${#missing[@]} -gt 0 ]; then
        log "ERROR: Missing tools: ${missing[*]}"
        log "Please install missing tools:"
        log "  - Subfinder: https://github.com/projectdiscovery/subfinder"
        log "  - Amass:     https://github.com/OWASP/Amass"
        log "  - httpx:     https://github.com/projectdiscovery/httpx"
        log "  - Katana:    https://github.com/projectdiscovery/katana"
        log "  - waybackurls: https://github.com/tomnomnom/waybackurls"
        log "  - gau:       https://github.com/lc/gau"
        log "  - Nuclei:    https://github.com/projectdiscovery/nuclei"
        exit 1
    fi
    log "All required tools are available."
}

# --- Main ----------------------------------------------------------
if [ -z "$TARGET" ]; then
    usage
fi

mkdir -p "$OUTPUT_DIR"
log "Starting enhanced reconnaissance for $TARGET"
log "Output will be stored in $OUTPUT_DIR"

# ----- Step 1: Subdomain enumeration (Subfinder + Amass) ----------
log "Step 1a: Running Subfinder..."
$SUBFINDER -d "$TARGET" -silent -o "${OUTPUT_DIR}/subfinder_domains.txt"

log "Step 1b: Running Amass (passive mode)..."
$AMASS enum -passive -d "$TARGET" -o "${OUTPUT_DIR}/amass_domains.txt"

# Combine and deduplicate subdomains
cat "${OUTPUT_DIR}/subfinder_domains.txt" "${OUTPUT_DIR}/amass_domains.txt" \
    | sort -u > "${OUTPUT_DIR}/all_subdomains.txt"
sub_count=$(wc -l < "${OUTPUT_DIR}/all_subdomains.txt")
log "Total unique subdomains found: $sub_count"

# ----- Step 2: Filter live subdomains -----------------------------
log "Step 2: Filtering live subdomains with httpx..."
$HTTPX -l "${OUTPUT_DIR}/all_subdomains.txt" -silent \
    -status-code -mc "$LIVE_STATUS_CODES" \
    -o "${OUTPUT_DIR}/live_domains.txt"
live_count=$(wc -l < "${OUTPUT_DIR}/live_domains.txt")
log "Identified $live_count live domains."

if [ "$live_count" -eq 0 ]; then
    log "No live domains found. Exiting."
    exit 0
fi

# ----- Step 3: Collect URLs from multiple sources -----------------
log "Step 3a: Crawling live domains with Katana..."
$KATANA -list "${OUTPUT_DIR}/live_domains.txt" -silent \
    -o "${OUTPUT_DIR}/katana_urls.txt" \
    -jc -fx -d 3

log "Step 3b: Fetching historical URLs with waybackurls..."
while IFS= read -r domain; do
    echo "$domain" | $WAYBACKURLS >> "${OUTPUT_DIR}/wayback_urls.txt"
done < "${OUTPUT_DIR}/live_domains.txt"

log "Step 3c: Fetching historical URLs with gau..."
while IFS= read -r domain; do
    $GAU "$domain" >> "${OUTPUT_DIR}/gau_urls.txt"
done < "${OUTPUT_DIR}/live_domains.txt"

# Combine all URLs, deduplicate
cat "${OUTPUT_DIR}/katana_urls.txt" \
    "${OUTPUT_DIR}/wayback_urls.txt" \
    "${OUTPUT_DIR}/gau_urls.txt" 2>/dev/null \
    | sort -u > "${OUTPUT_DIR}/all_urls.txt"
url_count=$(wc -l < "${OUTPUT_DIR}/all_urls.txt")
log "Total unique URLs collected: $url_count"

# ----- Step 4: Extract JavaScript files ---------------------------
log "Step 4: Extracting JavaScript files..."
grep -i "\.js" "${OUTPUT_DIR}/all_urls.txt" | sort -u > "${OUTPUT_DIR}/js_files.txt"
js_count=$(wc -l < "${OUTPUT_DIR}/js_files.txt")
log "Found $js_count JavaScript files."

if [ "$js_count" -eq 0 ]; then
    log "No JavaScript files found. Exiting."
    exit 0
fi

# ----- Step 5: Scan JS files with Nuclei --------------------------
log "Step 5: Scanning JS files with Nuclei (tags: $NUCLEI_TAGS)..."
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