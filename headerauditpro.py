#!/usr/bin/env python3
"""
HeaderAuditPro - Security Header Analyzer
Author: Ambuj Tiwari

Scan URLs for missing HTTP security headers and calculate a severity score.
"""

import argparse
import requests

REQUIRED_HEADERS = {
    "Content-Security-Policy": "High",
    "Strict-Transport-Security": "High",
    "X-Frame-Options": "Medium",
    "X-Content-Type-Options": "Medium",
    "Referrer-Policy": "Low",
    "X-XSS-Protection": "Low",
}

def check_headers(url: str) -> None:
    try:
        try:
            resp = requests.head(url, timeout=10, allow_redirects=True)
        except Exception:
            resp = requests.get(url, timeout=10, allow_redirects=True)

        headers = resp.headers
        print(f"\n[+] URL: {resp.url}")
        print(f"[+] Status: {resp.status_code}\n")

        missing = []
        present = []

        for h, sev in REQUIRED_HEADERS.items():
            if h in headers:
                present.append((h, sev, headers[h]))
            else:
                missing.append((h, sev))

        print("=== Present Headers ===")
        if present:
            for h, sev, val in present:
                print(f"{h} ({sev}) -> {val}")
        else:
            print("None of the recommended security headers are present.")

        print("\n=== Missing Headers ===")
        total_score = 0
        for h, sev in missing:
            print(f"{h} ({sev}) MISSING")
            if sev == "High":
                total_score += 3
            elif sev == "Medium":
                total_score += 2
            else:
                total_score += 1

        print(f"\n[+] Severity score: {total_score}")
        print("Created by: Ambuj Tiwari")

    except Exception as e:
        print(f"[!] Error fetching {url}: {e}")

def main() -> None:
    parser = argparse.ArgumentParser(
        description="HeaderAuditPro by Ambuj Tiwari - Security Header Analyzer"
    )
    parser.add_argument("-u", "--url", help="Single URL (https://example.com)")
    parser.add_argument("-l", "--list", help="File with URLs (one per line)")
    args = parser.parse_args()

    if args.url:
        check_headers(args.url)
    elif args.list:
        with open(args.list) as f:
            for line in f:
                url = line.strip()
                if url:
                    check_headers(url)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

