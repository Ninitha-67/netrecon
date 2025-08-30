import nmap
import requests
import os
import sys
from tabulate import tabulate

def scan_target(target):
    """Performs an Nmap scan with service version detection."""
    print(f"[+] Scanning {target} for open ports and services...")
    nm = nmap.PortScanner()
    try:
        # -sV enables service version detection
        nm.scan(target, arguments='-sV -T4')
        return nm
    except nmap.PortScannerError as e:
        print(f"[-] Nmap scan failed: {e}")
        return None

def get_vulnerabilities(service_name, version, api_key):
    """Queries the NVD API for vulnerabilities for a given service and version."""
    if not service_name or not version:
        return []
    
    # Construct a search query for the NVD API
    search_term = f"{service_name.strip()} {version.strip()}"
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {'keywordSearch': search_term, 'resultsPerPage': 3}
    headers = {'apiKey': api_key}
    
    try:
        response = requests.get(url, params=params, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        cves = []
        # Check if vulnerabilities were found
        if 'vulnerabilities' in data:
            for item in data['vulnerabilities']:
                cve = item['cve']
                cve_id = cve['id']
                description = cve['descriptions'][0]['value']
                # Get the CVSS v3 severity score if available
                cvss_score = "N/A"
                if 'metrics' in cve and 'cvssMetricV31' in cve['metrics']:
                    cvss_score = cve['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
                
                cves.append({
                    'id': cve_id,
                    'description': description,
                    'score': cvss_score
                })
        return cves
    
    except requests.exceptions.RequestException as e:
        print(f"[-] API request to NVD failed: {e}")
        return []

def main():
    api_key = os.getenv("NVD_API_KEY")
    if not api_key:
        print("[-] Error: NVD_API_KEY environment variable is not set.")
        sys.exit(1)
        
    target_host = input("Enter target IP or hostname: ")
    scanner = scan_target(target_host)
    
    if not scanner or not scanner.all_hosts():
        print("[-] No hosts found or scan failed.")
        return
        
    print(f"\nResults for {target_host}")
    
    all_results = []
    
    for host in scanner.all_hosts():
        if scanner[host].state() == 'up':
            for proto in scanner[host].all_protocols():
                ports = scanner[host][proto].keys()
                for port in ports:
                    service_info = scanner[host][proto][port]
                    service = service_info.get("name", "Unknown")
                    version = service_info.get("version", "Unknown")
                    
                    vulnerabilities = []
                    # Only search for vulnerabilities if service and version are found
                    if service != 'Unknown' and version != 'Unknown':
                        vulnerabilities = get_vulnerabilities(service, version, api_key)
                    if not version.strip():
                        version = "Unknown"
                    
                    cve_list = []
                    if vulnerabilities:
                        for cve in vulnerabilities[:3]: # Limit to top 3 for cleaner report
                            cve_id = cve['id']
                            cve_score = cve['score']
                            cve_list.append(f"{cve_id} (Score: {cve_score})")
                    else:
                        cve_list.append("None Found")
                    
                    all_results.append([port, service, version, "\n".join(cve_list)])

    headers = ["Port", "Service", "Version", "CVEs (Top 3)"]
    print(tabulate(all_results, headers=headers, tablefmt="fancy_grid"))

if __name__ == "__main__":
    main()