#!/usr/bin/env python3

import argparse
import requests

from modules.dns_enum import dns_bruteforce
from modules.port_scan import scan_ports
from modules.banner_grab import grab_banner
from modules.http_title import get_title
from modules.reporter import save_json, save_csv


def main():
    parser = argparse.ArgumentParser(
        description="AutoReconX – Automated Recon Tool"
    )
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-w", "--wordlist", default="wordlists/subdomains.txt")
    parser.add_argument("-o", "--output", default="output/results")
    args = parser.parse_args()

    print("\n[+] AutoReconX Scan Initialized")
    print(f"[+] Target Domain : {args.domain}\n")

    subs = dns_bruteforce(args.domain, args.wordlist)

    if args.domain not in subs:
        subs.append(args.domain)

    results = []
    total_ports = 0

    for sub in subs:
        print(f"\n[+] Subdomain: {sub}")

        ports = scan_ports(sub)
        total_ports += len(ports)

        title = get_title(sub)

        banners = {}
        for port in ports:
            banners[port] = grab_banner(sub, port)

        print(f"    Open Ports : {ports if ports else 'None'}")
        print(f"    HTTP Title : {title}")
        print(f"    Banner     : {banners}")

        results.append({
            "subdomain": sub,
            "ports": ports,
            "title": title,
            "banners": banners
        })

    save_json(results, args.output + ".json")
    save_csv(results, args.output + ".csv")

    print("\n[+] Scan Summary")
    print(f"    Total Subdomains : {len(subs)}")
    print(f"    Total Open Ports : {total_ports}")

    print("\n[+] Output Files")
    print(f"    {args.output}.json")
    print(f"    {args.output}.csv")

    print("\n[+] Scan completed successfully\n")


if __name__ == "__main__":
    main()

