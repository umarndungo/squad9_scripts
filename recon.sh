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

# DNSEnum
echo "[+] Running dnsenum..."
dnsenum "$DOMAIN" > "dnsenum.txt" 2>&1

# WhatWeb
echo "[+] Running whatweb..."
whatweb "https://$DOMAIN" > "whatweb.txt"

# Subfinder for subdomains
echo "[+] Running subfinder..."
subfinder -all -silent -d "$DOMAIN" -o "subfinder.txt"

# Subfinder with httpx for live hosts
echo "[+] Running subfinder with httpx..."
subfinder -all -silent -d "$DOMAIN" | httpx -silent > "subfinder_live.txt"

# Subfinder with httpx and katana
echo "[+] Running subfinder with httpx and katana..."
subfinder -all -silent -d "$DOMAIN" | httpx -silent | katana -f ufile > "katana.txt"

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

echo "========================================="
echo "[+] Reconnaissance completed!"
echo "[+] Results saved in $OUTPUT_DIR"
echo "[+] Files created:"
ls -la