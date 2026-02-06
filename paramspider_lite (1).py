#!/usr/bin/env python3
import argparse, requests, re
from urllib.parse import urlparse, urljoin, parse_qsl

requests.packages.urllib3.disable_warnings()

# 1) URL COLLECTOR
def collect_urls(base_url, max_pages=30):
    seen = set([base_url])
    to_visit = [base_url]
    collected = []

    while to_visit and len(collected) < max_pages:
        url = to_visit.pop(0)
        try:
            r = requests.get(url, timeout=8, verify=False)
        except:
            continue

        collected.append(url)

        for m in re.findall(r'href=["\']([^"\']+)["\']', r.text, re.I):
            if m.startswith("#") or m.lower().startswith("javascript:"):
                continue
            full = urljoin(url, m)
            if urlparse(full).netloc == urlparse(base_url).netloc and full not in seen:
                seen.add(full)
                to_visit.append(full)
    return collected

# 2) PARSE PARAMETERS
def extract_params(urls):
    found = {}
    for u in urls:
        query = urlparse(u).query
        if not query:
            continue
        for k, v in parse_qsl(query, keep_blank_values=True):
            found.setdefault(k, set()).add(u)
    return found

# 3) REFLECTION TESTING
TEST_WORDS = ["xss123", "testparam", "ambujtiwari"]

def reflect_test(url, param):
    for payload in TEST_WORDS:
        try:
            r = requests.get(url, params={param: payload}, timeout=8, verify=False)
            if payload in r.text:
                return True
        except:
            pass
    return False

# 4) MAIN + REPORTING
def main():
    parser = argparse.ArgumentParser(
        description="ParamSpider-Lite by Ambuj Tiwari - Parameter Discovery Tool"
    )
    parser.add_argument("-u", "--url", required=True,
                        help="Target URL (e.g. http://testphp.vulnweb.com/)")
    args = parser.parse_args()

    print(f"[+] Collecting URLs from {args.url}")
    urls = collect_urls(args.url)
    print(f"[+] Collected {len(urls)} URLs")

    params = extract_params(urls)
    print(f"[+] Unique parameters found: {len(params)}")

    print("\n=== REPORT ===")
    for p, ulist in params.items():
        sample_url = list(ulist)[0]
        reflected = reflect_test(sample_url, p)
        status = "REFLECTED" if reflected else "not reflected"
        print(f"\nParam: {p} ({status})")
        for u in ulist:
            print(f"  - {u}")

if __name__ == "__main__":
    main()

