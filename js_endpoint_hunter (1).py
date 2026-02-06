#!/usr/bin/env python3
"""
JS Endpoint Hunter by Ambuj Tiwari
Extract endpoints, API keys from JS files using regex.
"""
import re
import requests
import sys
from urllib.parse import urljoin, urlparse
import argparse

# Regex patterns for endpoints and secrets
ENDPOINT_PATTERNS = [
    r'["\'](/[^"\']*?\.(json?|xml|api|graphql|endpoint)["\'])',
    r'["\'](https?://[^"\']*?\.(json?|xml|api))["\']',
    r'fetch\s*\(\s*["\']([^"\']+)',
    r'ajax\s*\(\s*["\']([^"\']+)'
]
API_KEY_PATTERNS = [
    r'(api[_-]?key|token|secret)[=:]\s*["\']([^"\']+)["\']',
    r'["\']([a-zA-Z0-9]{32,}|[A-Za-z0-9+/]{40,}={0,2})["\']'  # Generic keys
]

def fetch_js_files(base_url, max_depth=2):
    """Crawl JS files from domain."""
    js_files = []
    visited = set()
    queue = [(base_url, 0)]
    while queue:
        url, depth = queue.pop(0)
        if url in visited or depth > max_depth:
            continue
        visited.add(url)
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                # Extract JS links
                js_links = re.findall(r'href=["\']([^"\']*\.js[^"\']*)["\']', resp.text, re.I)
                for link in js_links:
                    full_url = urljoin(url, link)
                    js_files.append(full_url)
                    queue.append((full_url, depth + 1))
        except:
            pass
    return list(set(js_files))

def analyze_js(js_url):
    """Analyze JS file for endpoints and keys."""
    try:
        resp = requests.get(js_url, timeout=10)
        content = resp.text
        endpoints = set()
        api_keys = set()
        
        for pat in ENDPOINT_PATTERNS:
            endpoints.update(re.findall(pat, content, re.I))
        for pat in API_KEY_PATTERNS:
            api_keys.update(re.findall(pat, content, re.I))
        
        return endpoints, api_keys
    except:
        return set(), set()

def main():
    parser = argparse.ArgumentParser(description="JS Endpoint Hunter by Ambuj Tiwari")
    parser.add_argument('-u', '--url', required=True, help='Target domain/URL')
    parser.add_argument('-d', '--depth', type=int, default=2, help='Crawl depth')
    args = parser.parse_args()
    
    print(f"[+] Crawling JS from {args.url}")
    js_files = fetch_js_files(args.url, args.depth)
    print(f"[+] Found {len(js_files)} JS files")
    
    all_endpoints = set()
    all_keys = set()
    for js in js_files:
        eps, keys = analyze_js(js)
        all_endpoints.update(eps)
        all_keys.update(keys)
        print(f"\n[+] {js}")
        print("Endpoints:", eps)
        print("API Keys:", keys)
    
    print(f"\n=== SUMMARY ===")
    print("Unique Endpoints:", sorted(all_endpoints))
    print("Potential Keys:", sorted(all_keys))

if __name__ == "__main__":
    main()
