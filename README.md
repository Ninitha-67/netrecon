<<<<<<< HEAD
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

```netrecon/
├── main.py    # Entry point: scan + CVE lookup + report generation
├── recon.py       # Core Nmap scanning and service enumeration functions
├── requirements.txt   # Python dependencies
├── scan_report.json   # Generated JSON report of scan results
├── .env               # Optional: Store NVD_API_KEY securely
└── README.md          # Project overview and instructions
```

---

## 🚀 How to Run

### 1️⃣ Clone the repository:
```
git clone https://github.com/Ninitha-67/netrecon.git
cd netrecon
```
### 2️⃣ Install dependencies:
```
pip install -r requirements.txt
```
### 3️⃣ (Optional) Set NVD API key for vulnerability lookups:

Windows (PowerShell):
```
$env:NVD_API_KEY="your_api_key_here"
```
### 4️⃣ Run the tool:
```

python main.py
```
---

## ⚠️ Disclaimer

This project is strictly for educational purposes. Do NOT scan or exploit networks without permission. Always follow responsible disclosure practices.

---

## 👩‍💻 Author

-Ninitha P – final Year BCA Student | Cybersecurity Enthusiast
-Guided by mentors for academic research & SOC tools

---