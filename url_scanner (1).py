#!/usr/bin/env python3
import sys
import socket

if len(sys.argv) != 2:
    print("Usage: url_scanner <domain>")
    sys.exit(1)

domain = sys.argv[1]

try:
    ip = socket.gethostbyname(domain)
    print(f"[+] Domain: {domain}")
    print(f"[+] IP Address: {ip}")
except socket.gaierror:
    print("[-] Invalid domain")

