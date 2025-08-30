#!/usr/bin/env python3
"""
main.py - Network Recon + Improved NVD CVE Lookup

Features:
- Nmap-based scan with -sV (service/version detection)
- Graceful handling of Unknown versions
- Fuzzy NVD searches (product+version, product+major, product)
- CVSS extraction v3.1, v3.0, v2
- Tabulated console output + JSON report
"""

import os
import time
import json
import requests
import traceback
from tabulate import tabulate

# optional: loads .env into environment
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# Try to import python-nmap (recommended). If not installed, instruct user.
try:
    import nmap
except Exception as e:
    print("ERROR: python-nmap is required. Install with: pip install python-nmap")
    raise

NVD_API_KEY = os.getenv("NVD_API_KEY", "").strip()
NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HEADERS = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}

# ---------- Helpers ----------

def extract_cvss_score(cve_obj):
    """Extract CVSS score from NVD CVE object, try v3.1, v3.0, then v2."""
    metrics = cve_obj.get("cve", {}).get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and isinstance(metrics[key], list) and metrics[key]:
            try:
                score = metrics[key][0].get("cvssData", {}).get("baseScore")
                if score is not None:
                    return score
            except Exception:
                continue
    return "N/A"

def build_search_terms(product, version):
    """Return list of search terms (from most-specific to broad)."""
    terms = []
    if product:
        if version and version != "Unknown":
            # full product + version
            terms.append(f"{product} {version}")
            # product + major version (e.g., 2.4)
            parts = version.split(".")
            if len(parts) >= 2:
                terms.append(f"{product} {parts[0]}.{parts[1]}")
            # product + major only
            terms.append(f"{product} {parts[0]}")
        # finally product only
        terms.append(product)
    return terms

def query_nvd(keyword, results_per_page=10):
    """Query NVD with keywordSearch; returns list of vulnerabilities (raw items)."""
    if not NVD_API_KEY:
        return {"error": "no_api_key", "items": []}
    params = {"keywordSearch": keyword, "resultsPerPage": results_per_page}
    try:
        resp = requests.get(NVD_BASE, headers=HEADERS, params=params, timeout=12)
        resp.raise_for_status()
        data = resp.json()
        items = data.get("vulnerabilities", [])
        return {"error": None, "items": items}
    except requests.exceptions.HTTPError as he:
        # 404 or 400 etc
        return {"error": f"http_error: {he}", "items": []}
    except Exception as e:
        return {"error": f"exception: {e}", "items": []}

def get_cves_for_product(product, version, limit_per_term=5):
    """Try multiple search terms and return deduplicated list of CVEs with score & short desc."""
    if not product:
        return []

    seen = set()
    results = []
    terms = build_search_terms(product, version)
    for term in terms:
        # small polite delay to avoid throttling
        time.sleep(1.2)
        res = query_nvd(term, results_per_page=limit_per_term)
        if res["error"]:
            # If no API key or HTTP error, stop trying
            # (but continue if it's safe; here we record error for debugging)
            # We do not raise to keep tool robust.
            # print(f"[!] NVD query error for '{term}': {res['error']}")
            continue
        for item in res["items"]:
            try:
                cve_obj = item.get("cve", {})
                cve_id = cve_obj.get("id")
                if not cve_id or cve_id in seen:
                    continue
                seen.add(cve_id)
                desc = cve_obj.get("descriptions", [{}])[0].get("value", "No description").strip()
                score = extract_cvss_score(item)
                results.append({"id": cve_id, "score": score, "desc": desc})
            except Exception:
                continue
        # stop early if we already have some results
        if results:
            break
    return results

# ---------- Scanning & Reporting ----------

def scan_target_with_nmap(target):
    """Run nmap -sV on the target and return structured results."""
    scanner = nmap.PortScanner()
    try:
        # -sV = service/version detection, -T4 faster timing, -Pn skip host discovery for likely firewalled hosts optional
        scanner.scan(hosts=target, arguments='-sV -T4')
    except nmap.PortScannerError as e:
        print(f"[-] Nmap error: {e}")
        return None
    except Exception as e:
        print(f"[-] Unexpected error running nmap: {e}")
        return None

    results = []
    hosts = scanner.all_hosts()
    if not hosts:
        return results

    for host in hosts:
        hoststate = scanner[host].state()
        if hoststate != "up":
            continue
        for proto in scanner[host].all_protocols():
            ports = sorted(scanner[host][proto].keys())
            for port in ports:
                info = scanner[host][proto][port]
                service = info.get("name", "Unknown") or "Unknown"
                product = info.get("product", "")
                version = info.get("version", "")
                # nmap sometimes provides 'product' and 'version' separately; construct readable product string
                if product:
                    product_full = (product + (" " + version if version else "")).strip()
                else:
                    # try 'extrainfo' or 'servicefp' fallback
                    product_full = version or info.get("extrainfo", "") or "Unknown"
                # normalize
                if not product_full:
                    product_full = "Unknown"
                # Also keep product and version separately for better NVD queries
                results.append({
                    "host": host,
                    "port": port,
                    "proto": proto,
                    "service": service,
                    "product": product or "Unknown",
                    "version": version or "Unknown",
                    "product_full": product_full
                })
    return results

def generate_tabular_report(scan_entries, save_json=True, json_path="scan_report.json"):
    """Create table and (optionally) save JSON report."""
    table_rows = []
    json_out = []
    for entry in scan_entries:
        host = entry["host"]
        port = entry["port"]
        proto = entry["proto"]
        service = entry["service"]
        product = entry["product"]
        version = entry["version"]
        product_full = entry["product_full"]

        # Query NVD with product and version using fuzzy approach
        cves = get_cves_for_product(product if product != "Unknown" else service, version)
        if not cves:
            cve_summary = "None Found"
        else:
            # create short strings for top 3
            cve_summary = "\n".join([f"{c['id']} (Score: {c['score']})" for c in cves[:3]])

        table_rows.append([host, port, proto, service, product, version, cve_summary])
        json_out.append({
            "host": host,
            "port": port,
            "proto": proto,
            "service": service,
            "product": product,
            "version": version,
            "cves": cves
        })

    headers = ["Host", "Port", "Proto", "Service", "Product", "Version", "CVEs (top 3)"]
    print("\n" + tabulate(table_rows, headers=headers, tablefmt="fancy_grid"))

    if save_json:
        try:
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(json_out, f, indent=2, ensure_ascii=False)
            print(f"\n[✔] JSON report saved to {json_path}")
        except Exception as e:
            print(f"[!] Failed to save JSON report: {e}")

# ---------- CLI flow ----------

def main():
    print("=== Network Recon & Improved Vulnerability Lookup ===")
    target = input("Enter target IP or hostname: ").strip()
    if not target:
        print("No target given. Exiting.")
        return

    print(f"[+] Scanning {target} (this may take a few seconds)...")
    scan_entries = scan_target_with_nmap(target)
    if scan_entries is None:
        print("Scan failed (see errors above).")
        return
    if not scan_entries:
        print("No hosts/ports found (host down or no open ports detected).")
        return

    # Normalize: ensure unknown versions are explicit (done in scan function)
    # Show initial discovered ports
    for e in scan_entries:
        print(f"  -> {e['host']}:{e['port']}/{e['proto']}  service={e['service']}  product={e['product']}  version={e['version']}")

    if not NVD_API_KEY:
        print("\n[!] NVD API key not set. CVE lookups will be skipped. Set NVD_API_KEY in env or .env to enable.")
    else:
        print("\n[+] NVD API key found: enabling vulnerability lookups.")

    # Generate report (will attempt CVE queries only if API key present)
    generate_tabular_report(scan_entries)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Exiting.")
    except Exception:
        print("\n[!] Unexpected error:")
        traceback.print_exc()
