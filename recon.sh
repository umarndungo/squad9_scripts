#!/bin/bash

# Check if domain is supplied
if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    echo "Example: $0 example.com"
    exit 1
fi

DOMAIN="$1"
OUTPUT_DIR="recon_${DOMAIN}"

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

# WhatWeb
echo "[+] Running whatweb..."
whatweb "https://$DOMAIN" > "whatweb.txt"

# Subfinder with httpx and katana
echo "[+] Running subfinder with httpx and katana..."
subfinder -all -silent -d "$DOMAIN" | httpx -silent > "temp_urls.txt"
katana -list temp_urls.txt -o "katana.txt"
rm temp_urls.txt

# WAFW00F
echo "[+] Running wafw00f..."
wafw00f -a -l "$DOMAIN" > "wafw00f.txt"

# Nmap scan
echo "[+] Running nmap..."
nmap -sV -sS -sC -T4 --open "$DOMAIN" > "nmap.txt"

# WPScan (if WordPress is detected)
echo "[+] Running wpscan..."
wpscan --random-user-agent --url "https://$DOMAIN" > "wpscan.txt" 2>&1

# Gobuster directory enumeration
echo "[+] Running gobuster..."
gobuster dir -u "https://$DOMAIN" -w /usr/share/wordlists/dirb/common.txt --no-error > "gobuster.txt"

# DNSEnum
echo "[+] Running dnsenum..."
dnsenum "$DOMAIN" > "dnsenum.txt" 2>&1

echo "========================================="
echo "[+] Reconnaissance completed!"
echo "[+] Results saved in $OUTPUT_DIR"
echo "[+] Files created:"
ls -la