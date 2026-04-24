#!/usr/bin/env python3
"""ReconXpose scanner and dashboard launcher.

Features:
- Multi-target Nmap scanning
- Service/version detection
- Best-effort OS detection
- Optional NVD enrichment
- Static demo Shodan and email alert panels
- HTML report generation and Flask dashboard mode
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import socket
import smtplib
import time
import traceback
from pathlib import Path
from email.message import EmailMessage

import requests

from report_generator import create_app, generate_html_report

try:
    from dotenv import load_dotenv

    load_dotenv()
except Exception:
    pass

try:
    import nmap
except Exception as exc:
    raise SystemExit("python-nmap is required. Install it with: pip install python-nmap") from exc

try:
    from tabulate import tabulate
except Exception:
    tabulate = None


NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY", "").strip()
HEADERS = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
JSON_PATH = Path("scan_report.json")
HTML_PATH = Path("reconxpose_report.html")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "").strip()
SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587").strip() or "587")
SMTP_USER = os.getenv("SMTP_USER", "").strip()
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "").strip()
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").strip().lower() not in {"0", "false", "no"}
ALERT_FROM_EMAIL = os.getenv("ALERT_FROM_EMAIL", SMTP_USER).strip()
ALERT_TO_EMAIL = os.getenv("ALERT_TO_EMAIL", "").strip()


def extract_cvss_score(cve_item: dict) -> str | float:
    metrics = cve_item.get("cve", {}).get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key)
        if not values:
            continue
        try:
            score = values[0].get("cvssData", {}).get("baseScore")
            if score is not None:
                return score
        except Exception:
            continue
    return "N/A"


def build_search_terms(product: str, version: str) -> list[str]:
    product = (product or "").strip()
    version = (version or "").strip()
    if not product:
        return []

    terms: list[str] = []
    if version and version != "Unknown":
        terms.append(f"{product} {version}")
        parts = version.split(".")
        if len(parts) >= 2:
            terms.append(f"{product} {parts[0]}.{parts[1]}")
        if parts:
            terms.append(f"{product} {parts[0]}")
    terms.append(product)
    return list(dict.fromkeys(terms))


def query_nvd(keyword: str, results_per_page: int = 10) -> list[dict]:
    if not NVD_API_KEY:
        return []
    params = {"keywordSearch": keyword, "resultsPerPage": results_per_page}
    response = requests.get(NVD_BASE, headers=HEADERS, params=params, timeout=12)
    response.raise_for_status()
    return response.json().get("vulnerabilities", [])


def get_cves_for_product(product: str, version: str, limit_per_term: int = 5) -> list[dict]:
    if not product or not NVD_API_KEY:
        return []

    seen: set[str] = set()
    results: list[dict] = []

    for term in build_search_terms(product, version):
        time.sleep(0.5)
        try:
            items = query_nvd(term, results_per_page=limit_per_term)
        except Exception:
            continue

        for item in items:
            try:
                cve = item.get("cve", {})
                cve_id = cve.get("id")
                if not cve_id or cve_id in seen:
                    continue
                descriptions = cve.get("descriptions", [])
                description = descriptions[0].get("value", "No description") if descriptions else "No description"
                results.append({"id": cve_id, "score": extract_cvss_score(item), "desc": description.strip()})
                seen.add(cve_id)
            except Exception:
                continue

        if results:
            break

    return results


def lookup_shodan(host: str) -> dict:
    if not SHODAN_API_KEY:
        return {
            "status": "unavailable",
            "summary": "Set SHODAN_API_KEY to enable live lookups.",
            "exposure": "No live Shodan data available.",
        }

    try:
        url = f"https://api.shodan.io/shodan/host/{host}"
        response = requests.get(url, params={"key": SHODAN_API_KEY}, timeout=15)
        response.raise_for_status()
        data = response.json()
        ports = data.get("ports", [])
        org = data.get("org") or data.get("isp") or "Unknown"
        country = data.get("country_name") or data.get("country_code") or "Unknown"
        vulns = data.get("vulns", {})
        vuln_count = len(vulns) if isinstance(vulns, dict) else 0
        return {
            "status": "live",
            "summary": f"Shodan found {len(ports)} exposed ports for {host}.",
            "exposure": f"Org: {org} | Country: {country} | Vulns: {vuln_count}",
            "ports": ports[:12],
        }
    except Exception as exc:
        return {
            "status": "error",
            "summary": "Shodan lookup failed.",
            "exposure": str(exc),
        }


def send_critical_cve_email(target: str, critical_cves: list[dict]) -> dict:
    if not critical_cves:
        return {"status": "not_sent", "message": "No critical CVEs to alert."}
    if not (SMTP_HOST and SMTP_USER and SMTP_PASSWORD and ALERT_TO_EMAIL):
        return {"status": "unavailable", "message": "Set SMTP_HOST, SMTP_USER, SMTP_PASSWORD, and ALERT_TO_EMAIL."}

    subject = f"ReconXpose critical CVE alert for {target}"
    body_lines = [f"Critical CVEs detected for {target}:", ""]
    for cve in critical_cves[:5]:
        body_lines.append(f"- {cve['id']} (Score: {cve['score']})")
        body_lines.append(f"  {cve['desc']}")
    body = "\n".join(body_lines)

    msg = EmailMessage()
    msg["From"] = ALERT_FROM_EMAIL or SMTP_USER
    msg["To"] = ALERT_TO_EMAIL
    msg["Subject"] = subject
    msg.set_content(body)

    try:
        if SMTP_USE_TLS:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as server:
                server.starttls()
                server.login(SMTP_USER, SMTP_PASSWORD)
                server.send_message(msg)
        else:
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=20) as server:
                server.login(SMTP_USER, SMTP_PASSWORD)
                server.send_message(msg)
        return {"status": "sent", "message": f"Critical CVE email sent to {ALERT_TO_EMAIL}."}
    except Exception as exc:
        return {"status": "error", "message": str(exc)}


def resolve_host_label(host: str) -> str:
    try:
        return socket.gethostbyaddr(host)[0]
    except Exception:
        return host


def parse_targets(raw_target: str) -> list[str]:
    parts = [item.strip() for item in raw_target.replace("\n", ",").split(",")]
    return [item for item in parts if item]


def scan_target_with_nmap(target: str) -> list[dict] | None:
    scanner = nmap.PortScanner()
    try:
        scanner.scan(hosts=target, arguments="-sV -O --osscan-guess -T4")
    except nmap.PortScannerError as exc:
        print(f"[-] Nmap error: {exc}")
        return None
    except Exception as exc:
        print(f"[-] Nmap error: {exc}")
        return None

    results: list[dict] = []
    for host in scanner.all_hosts():
        if scanner[host].state() != "up":
            continue

        os_guess = "Unknown"
        try:
            osmatch = scanner[host].get("osmatch", [])
            if osmatch:
                os_guess = osmatch[0].get("name", "Unknown") or "Unknown"
        except Exception:
            pass

        for proto in scanner[host].all_protocols():
            for port in sorted(scanner[host][proto].keys()):
                info = scanner[host][proto][port]
                service = info.get("name") or "Unknown"
                product = info.get("product") or "Unknown"
                version = info.get("version") or "Unknown"
                results.append(
                    {
                        "host": host,
                        "host_label": resolve_host_label(host),
                        "port": port,
                        "proto": proto,
                        "service": service,
                        "product": product,
                        "version": version,
                        "os": os_guess,
                    }
                )

    return results


def scan_many_targets(targets: list[str]) -> list[dict]:
    results: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(4, max(1, len(targets)))) as pool:
        future_map = {pool.submit(scan_target_with_nmap, target): target for target in targets}
        for future in concurrent.futures.as_completed(future_map):
            target = future_map[future]
            entries = future.result()
            if entries is None:
                print(f"[-] Scan failed for {target}")
                continue
            results.extend(entries)
    return results


def enrich_scan_entries(scan_entries: list[dict]) -> list[dict]:
    enriched: list[dict] = []
    for entry in scan_entries:
        product_name = entry["product"] if entry["product"] != "Unknown" else entry["service"]
        cves = get_cves_for_product(product_name, entry["version"])
        critical = [item for item in cves if isinstance(item.get("score"), (int, float)) and float(item["score"]) >= 7.0]
        shodan_data = lookup_shodan(entry["host"])
        enriched.append(
            {
                **entry,
                "cves": cves,
                "shodan": shodan_data,
                "alert": send_critical_cve_email(entry["host"], critical),
            }
        )
    return enriched


def execute_scan(raw_target: str, log: bool = True) -> list[dict] | None:
    targets = parse_targets(raw_target)
    if not targets:
        if log:
            print("No target given. Exiting.")
        return None

    if log:
        if len(targets) == 1:
            print(f"[+] Scanning {targets[0]} (this may take a few seconds)...")
        else:
            print(f"[+] Scanning {len(targets)} targets (this may take a few seconds)...")

    scan_entries = scan_many_targets(targets)
    if not scan_entries:
        if log:
            print("No hosts/ports found (host down or no open ports detected).")
        return []

    if log:
        for entry in scan_entries:
            print(
                f"  -> {entry['host']}:{entry['port']}/{entry['proto']}  "
                f"service={entry['service']}  product={entry['product']}  version={entry['version']}  os={entry['os']}"
            )

        if NVD_API_KEY:
            print("\n[+] NVD API key found: enabling vulnerability lookups.")
        else:
            print("\n[!] NVD API key not set. CVE lookups will be skipped.")
            print("    Set NVD_API_KEY in your environment or .env file to enable CVE enrichment.")

    return enrich_scan_entries(scan_entries)


def print_results_table(entries: list[dict]) -> None:
    rows = []
    for entry in entries:
        cve_summary = "None Found"
        if entry.get("cves"):
            cve_summary = "\n".join(f"{cve['id']} (Score: {cve['score']})" for cve in entry["cves"][:3])
        rows.append(
            [
                entry["host"],
                entry["port"],
                entry["proto"],
                entry["service"],
                entry["product"],
                entry["version"],
                entry["os"],
                cve_summary,
            ]
        )

    headers = ["Host", "Port", "Proto", "Service", "Product", "Version", "OS", "CVEs (top 3)"]
    if tabulate:
        print("\n" + tabulate(rows, headers=headers, tablefmt="grid"))
    else:
        print("\n" + " | ".join(headers))
        for row in rows:
            print(" | ".join(str(item) for item in row))


def save_reports(entries: list[dict], json_path: Path = JSON_PATH, html_path: Path = HTML_PATH) -> None:
    json_path.write_text(json.dumps(entries, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n[OK] JSON report saved to {json_path}")
    time.sleep(0.5)
    generate_html_report(json_path, html_path)


def run_cli(raw_target: str) -> None:
    enriched_entries = execute_scan(raw_target, log=True)
    if enriched_entries is None:
        return
    print_results_table(enriched_entries)
    save_reports(enriched_entries)


def run_scan_callback(raw_target: str) -> bool:
    enriched_entries = execute_scan(raw_target, log=False)
    if enriched_entries is None:
        return False
    if not enriched_entries:
        return False
    print_results_table(enriched_entries)
    save_reports(enriched_entries)
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="ReconXpose network recon and dashboard tool")
    parser.add_argument("target", nargs="?", help="Target IP, hostname, subnet, or comma-separated list")
    parser.add_argument("--web", action="store_true", help="Run the Flask dashboard server")
    parser.add_argument("--host", default="127.0.0.1", help="Flask host")
    parser.add_argument("--port", default=5000, type=int, help="Flask port")
    args = parser.parse_args()

    if args.web:
        app = create_app(JSON_PATH, HTML_PATH, run_scan_callback)
        app.run(host=args.host, port=args.port, debug=False)
        return

    print("=== ReconXpose ===")
    target = args.target or input("Enter target IP, range, or hostname: ").strip()
    run_cli(target)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Exiting.")
    except Exception:
        print("\n[!] Unexpected error:")
        traceback.print_exc()
