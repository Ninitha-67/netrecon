# ReconXpose

Network reconnaissance and vulnerability reporting tool with CLI and Flask dashboard modes.

## Features

- Multi-target Nmap scanning
- Service/version enumeration
- Best-effort OS detection
- Optional NVD CVE enrichment
- Real Shodan host lookups
- Real SMTP email alerts for critical CVEs
- HTML dashboard report
- Flask dashboard viewer

## Requirements

- Python 3
- Nmap installed on the system

## Install

```bash
pip install -r requirements.txt
```

## Optional environment variables

Set your NVD API key if you want CVE enrichment:

```powershell
$env:NVD_API_KEY="your_api_key_here"
```

You can also place it in a `.env` file.

Shodan:

```powershell
$env:SHODAN_API_KEY="your_shodan_key"
```

SMTP alerts:

```powershell
$env:SMTP_HOST="smtp.gmail.com"
$env:SMTP_PORT="587"
$env:SMTP_USER="your_email@example.com"
$env:SMTP_PASSWORD="your_app_password"
$env:ALERT_FROM_EMAIL="your_email@example.com"
$env:ALERT_TO_EMAIL="target_email@example.com"
```

Optional:

```powershell
$env:SMTP_USE_TLS="true"
```

## Run CLI scan

```bash
python main.py 127.0.0.1
```

Multiple targets:

```bash
python main.py "127.0.0.1,scanme.nmap.org"
```

## Run dashboard

```bash
python main.py --web
```

Then open `http://127.0.0.1:5000`.

## Output

- `scan_report.json`
- `reconxpose_report.html`

## Author

- Ninitha P – Final Year BCA Student | Cybersecurity Enthusiast
- Guided by mentors for academic research and SOC tooling

## Disclaimer

Use only on systems you are authorized to test.
