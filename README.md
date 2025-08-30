# 🔍 NetRecon – Network Recon & Vulnerability Scanner

A Python-based offensive security tool that performs **network reconnaissance**, identifies open ports, detects services and versions, and queries the **NVD database for vulnerabilities (CVEs)**. This tool generates **tabular console reports** and a **JSON report** for analysis.

---

## 🚀 Project Overview
NetRecon automates network scanning and vulnerability enumeration using:

- **Nmap** for port scanning and service/version detection
- **Requests** to query the NVD API for CVE information
- **Tabulate** for structured console output
- **JSON report generation** for further analysis

It’s designed for **educational purposes** and ethical hacking practice in controlled environments.

---

## 🎯 Key Features

- Port scanning and service/version detection using Nmap (`-sV`)
- Automatic lookup of vulnerabilities from NVD (CVE IDs + CVSS scores)
- Fuzzy search for vulnerabilities (full version, major version, product only)
- Tabulated console output for readability
- JSON report saved for record keeping
- Graceful handling of unknown versions and missing CVEs

---

## 🧰 Tools & Technologies

- **Python 3.11**
- **Libraries**: `python-nmap`, `requests`, `tabulate`, `python-dotenv`
- **NVD API** for vulnerability data
- **JSON** and **tabulate** for reporting

---

## 📦 Project Structure

