🔥 NetRecon - Network Reconnaissance & Vulnerability Scanning Tool (Offensive Cybersecurity + Python)  

A Python-based offensive security tool that automates the discovery of open ports, enumerates services, and identifies potential vulnerabilities using Nmap and the NVD (National Vulnerability Database) API.

---

🔥 **Overview:**  
NetRecon is designed for **network reconnaissance and vulnerability assessment**. It performs fast host discovery, port scanning, service enumeration, and CVE lookup to identify known vulnerabilities in detected services. The tool generates **structured tabulated output** in the console and saves a **JSON report** for analysis.

It simulates the initial stages of a red-team engagement, providing visibility into target systems and highlighting potential security weaknesses — all in a safe and controlled environment.

---

🎯 **Key Features:**  
- 🔍 **Host Discovery:** Resolves target hostname to IP and identifies live hosts  
- 🛡️ **Port Scanning:** Fast TCP scanning with `-sV` for service/version detection  
- 🧩 **Service Enumeration:** Captures service name, product, and version information  
- 📌 **Vulnerability Lookup:** Fetches CVEs using NVD API (supports fuzzy searches by product/version)  
- 📊 **Report Generation:** Console tabulated output + `scan_report.json` export  
- ⚠️ **Graceful Handling:** Shows `Unknown` for services/versions that Nmap cannot detect  
- ⏱️ **Automated Delay:** Handles NVD API throttling to avoid request errors  

---

🧰 **Tools & Technologies:**  
- Python 3.12  
- python-nmap (Nmap automation)  
- Requests (HTTP requests to NVD API)  
- Tabulate (Console report formatting)  
- python-dotenv (Optional: Load NVD API key from `.env`)  
- JSON (Structured report output)  

---

📦 **Folder Structure:**  
netrecon/
├── main.py # Entry point: scan + CVE lookup + report generation
├── recon.py # Core Nmap scanning and service enumeration functions
├── requirements.txt # Python dependencies
├── scan_report.json # Generated JSON report of scan results
├── .env # Optional: Store NVD_API_KEY securely
└── README.md # Project overview and instructions


---

🚀 **How to Run:**  

1. Clone the repository:

```bash
git clone https://github.com/Ninitha-67/netrecon.git
cd netrecon
Install dependencies:

pip install -r requirements.txt


(Optional) Set NVD API key for vulnerability lookups:

Windows (PowerShell):

$env:NVD_API_KEY="your_api_key_here"


Linux/macOS:

export NVD_API_KEY="your_api_key_here"


Run the tool:

python main.py


Follow the prompt to enter a target IP or hostname.

Tool scans for open ports, enumerates services, and fetches relevant CVEs.

Generates tabulated output and saves JSON report scan_report.json.
📄 Sample Output:
=== Network Recon & Improved Vulnerability Lookup ===
Enter target IP or hostname: scanme.nmap.org
[+] Scanning scanme.nmap.org...
  -> 45.33.32.156:22/tcp  service=ssh  product=OpenSSH  version=6.6.1p1
  -> 45.33.32.156:80/tcp  service=http  product=Apache httpd  version=2.4.7

╒══════════════╤════════╤═════════╤══════════════╤══════════════╤════════════════╤════════════════╕
│ Host         │ Port   │ Proto   │ Service      │ Product      │ Version        │ CVEs (top 3)   │
╞══════════════╪════════╪═════════╪══════════════╪══════════════╪════════════════╪════════════════╡
│ 45.33.32.156 │ 22     │ tcp     │ ssh          │ OpenSSH      │ 6.6.1p1        │ None Found      │
│ 45.33.32.156 │ 80     │ tcp     │ http         │ Apache httpd │ 2.4.7          │ None Found      │
╘══════════════╧════════╧═════════╧══════════════╧══════════════╧════════════════╧════════════════╛
⚠️ Disclaimer:
This tool is intended strictly for educational and ethical security testing.
Do NOT scan or exploit systems without explicit permission. Always follow responsible disclosure practices.

👩‍💻 Author:
Ninitha P – BCA Cybersecurity Student
LinkedIn

Developed for InlighnX Tech Internship and guided by mentors for academic research & SOC tools.