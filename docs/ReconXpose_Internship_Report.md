# ReconXpose Internship Report

## Title Page

Project Title: ReconXpose - Advanced Network Vulnerability Intelligence Platform

Submitted by: Ninit N

Program: Internship Project Report

Domain: Cyber Security / Network Reconnaissance

Institution: College Submission Copy

Academic Year: 2025-2026

---

## Declaration

I declare that the project work titled "ReconXpose" is an original work carried out by me during my internship project period. The content of this report is based on the implementation, testing, and analysis of the developed tool.

---

## Certificate

This is to certify that the project report titled "ReconXpose" has been successfully completed as an internship project and is submitted for external review.

---

## Acknowledgement

I express my sincere gratitude to my mentors, faculty members, and peers for their guidance and support throughout the development of ReconXpose. I also acknowledge the open-source community for the tools and libraries that made this project possible.

---

## Abstract

ReconXpose is a Python-based network reconnaissance and vulnerability intelligence platform designed to scan targets, enumerate services, detect operating systems, query the NVD vulnerability database, integrate Shodan exposure intelligence, and generate both HTML and interactive dashboard outputs. The tool was developed as an improved evolution of a basic network scanning project into a more complete security workflow. The objective was to create a practical, lightweight, and visually presentable security tool suitable for internship demonstration and academic evaluation. ReconXpose supports multi-target scanning, real-time report generation, CVE enrichment, dashboard visualization, and alert-driven analysis.

---

## Table of Contents

1. Introduction
2. Problem Statement
3. Objectives
4. Scope of the Project
5. Technology Stack
6. Literature Review / Related Tools
7. System Analysis
8. System Design
9. Implementation Details
10. Modules Description
11. Testing and Results
12. Limitations
13. Future Enhancements
14. Conclusion
15. References
16. Appendices

---

## 1. Introduction

Network reconnaissance is one of the first phases of security assessment and defensive exposure analysis. Before a system can be hardened, it is necessary to understand which hosts are visible, which ports are open, which services are running, what versions are exposed, and whether those services are associated with known vulnerabilities. Many existing tools cover only a single part of this workflow. Some tools scan ports, some provide passive intelligence, and some generate reports, but they often require multiple steps and separate outputs.

ReconXpose was built to combine the essential elements of reconnaissance and vulnerability intelligence into a single coherent workflow. The project focuses on practical usability, a polished presentation layer, and a lightweight architecture that can run on a standard Python environment. It supports both command-line scanning and a browser-based dashboard for review and demonstration.

This report documents the purpose, architecture, implementation, testing, and outcomes of the ReconXpose project.

## 2. Problem Statement

The primary problem addressed by ReconXpose is the fragmentation of typical reconnaissance workflows. In a basic workflow, an operator may use one tool for scanning, another for report generation, another for vulnerability lookup, and yet another for presentation. This makes the process slower, less consistent, and more difficult to demonstrate in an academic or internship setting.

The project needed to solve the following problems:

- How to scan one or more targets efficiently.
- How to enrich discovered services with CVE information.
- How to show the output in both machine-readable and human-readable formats.
- How to present the result in a dashboard that is clear enough for review and assessment.
- How to keep the tool lightweight and easy to execute in a lab environment.

## 3. Objectives

The objectives of ReconXpose were:

- To build a Python-based recon tool using Nmap.
- To detect services, product versions, and operating systems.
- To query NVD and associate discovered services with matching CVEs.
- To support multi-target scanning.
- To integrate Shodan exposure intelligence.
- To trigger email alerts for critical CVEs.
- To generate JSON and HTML reports.
- To provide a Flask dashboard with interactive visualization.
- To rename and rebrand the tool as ReconXpose for uniqueness.

## 4. Scope of the Project

The project scope includes active network scanning, enrichment from public vulnerability sources, report generation, and dashboard presentation. The project does not include exploitation, bypass, persistence, or offensive actions. It is intended for authorized lab targets, academic demonstration, and controlled internal use.

The tool is designed to work with:

- A single target host
- A comma-separated list of multiple targets
- Lab environments such as `scanme.nmap.org`
- Local hosts for smoke testing

## 5. Technology Stack

ReconXpose uses the following technologies:

- Python 3
- python-nmap
- requests
- tabulate
- python-dotenv
- Flask
- NVD API
- Shodan API
- SMTP email via Gmail or compatible providers

## 6. Literature Review / Related Tools

Several tools inspired the project design.

### 6.1 Nmap

Nmap is the core scanning engine used to discover live hosts, open ports, and service banners. It is widely used in security assessment because of its flexibility, speed, and maturity.

### 6.2 Shodan

Shodan is a search engine for internet-connected devices. It provides passive exposure intelligence and helps identify what the internet can already see about a host.

### 6.3 OpenVAS / Vulnerability Scanners

Traditional vulnerability scanners are powerful but often heavier to set up. They may require larger infrastructure or longer scan times. ReconXpose is designed as a lighter, more presentation-friendly workflow.

### 6.4 NVD

The NVD database is used to correlate discovered services with known CVEs. This adds vulnerability context to the raw scan results.

## 7. System Analysis

Before implementation, the project was analyzed as a pipeline consisting of input, discovery, enrichment, alerting, and reporting.

### 7.1 Input Layer

The input layer accepts one or more targets in a single command or through the dashboard.

### 7.2 Discovery Layer

Nmap is used to identify open ports and services. Service versions are extracted when available.

### 7.3 Enrichment Layer

The discovered product/version values are queried against NVD to obtain CVE matches.

### 7.4 Intelligence Layer

Shodan is used to obtain exposure information for live hosts when credentials are configured.

### 7.5 Alert Layer

Critical CVEs can trigger an email alert.

### 7.6 Output Layer

Outputs include JSON, HTML, and dashboard views.

## 8. System Design

The architecture is based on a modular separation of concerns.

### 8.1 Core Pipeline

The core pipeline flows as follows:

Input targets -> Host discovery -> Port + OS scan -> Service enumeration -> CVE + Shodan lookup -> Alert engine -> Report / Dashboard

### 8.2 Dashboard Design

The dashboard provides:

- Summary cards
- Risk overview meter
- Severity donut chart
- Top ports chart
- Search and filter controls
- Interactive host detail drawer
- Results table

### 8.3 Report Design

The static HTML report provides:

- A presentation-style summary
- Core engine cards
- Modules section
- Pipeline diagram
- Uniqueness comparison
- Technology stack
- Scan findings

## 9. Implementation Details

### 9.1 `main.py`

`main.py` is the command-line and dashboard launcher. It handles target parsing, Nmap scanning, CVE enrichment, Shodan lookup, email alerts, JSON writing, and report generation.

### 9.2 `report_generator.py`

This module renders both the static report and the interactive dashboard. It also exposes the Flask app and browser scan endpoint.

### 9.3 Environment Variables

The project uses environment variables for sensitive values:

- `NVD_API_KEY`
- `SHODAN_API_KEY`
- `SMTP_HOST`
- `SMTP_PORT`
- `SMTP_USER`
- `SMTP_PASSWORD`
- `ALERT_FROM_EMAIL`
- `ALERT_TO_EMAIL`
- `SMTP_USE_TLS`

## 10. Modules Description

### 10.1 Target Parsing Module

Parses single or multiple targets and supports comma-separated input.

### 10.2 Nmap Scanning Module

Scans targets for open ports, service names, service versions, and OS guesses.

### 10.3 CVE Lookup Module

Queries NVD using extracted product and version values.

### 10.4 Shodan Lookup Module

Looks up live hosts and summarizes exposure.

### 10.5 Email Alert Module

Sends a notification when critical CVEs are found.

### 10.6 JSON Report Module

Writes a structured machine-readable output file.

### 10.7 HTML Report Module

Produces a polished offline summary report.

### 10.8 Flask Dashboard Module

Displays scan results with charts, filters, and interactive controls.

## 11. Testing and Results

The tool was tested on:

- `127.0.0.1`
- `scanme.nmap.org`
- Multi-target input strings

### 11.1 Functional Checks

- Scan execution completed successfully.
- JSON report was generated.
- HTML report was generated.
- Dashboard loaded successfully.
- NVD CVE lookup returned matches.
- Shodan lookup worked when credentials were configured.
- Email alert path was verified with SMTP configuration.

### 11.2 Sample Observations

Sample scan output showed open ports such as SSH, SMTP, HTTP, MSRPC, and SMB-related services. The NVD enrichment produced CVE IDs and scores for matching services. The dashboard summarized the results using cards, severity meters, a donut visualization, and row-level detail views.

## 12. Limitations

Current limitations include:

- Dependence on external API keys for full intelligence features.
- Accuracy of CVE matching depends on Nmap product/version quality.
- Email delivery depends on SMTP provider settings.
- Shodan results may vary by host and available exposure.

## 13. Future Enhancements

Planned improvements include:

- Export to PDF directly from the tool.
- Host history and scan comparison.
- Save dashboard snapshots.
- Advanced charts and trend analysis.
- Role-based dashboard access.
- Better alert customization.

## 14. Conclusion

ReconXpose successfully evolved from a basic recon script into a complete vulnerability intelligence workflow. The project now supports active scanning, OS inference, CVE enrichment, live exposure intelligence, email alerting, and polished reporting. It is suitable for internship demonstration because it is practical, modular, presentable, and easy to explain in a live review.

## 15. References

- Nmap official documentation
- NVD API documentation
- Shodan API documentation
- Flask documentation
- Python requests documentation

## 16. Appendices

### Appendix A: Example Run Command

```powershell
python main.py "scanme.nmap.org"
```

### Appendix B: Dashboard Command

```powershell
python main.py --web
```

### Appendix C: Environment Setup

```powershell
$env:NVD_API_KEY="..."
$env:SHODAN_API_KEY="..."
$env:SMTP_HOST="smtp.gmail.com"
```

### Appendix D: Notes for Presentation

- Start with the problem statement.
- Show CLI scan output.
- Show the HTML report.
- Show the dashboard.
- Explain what is live and what is configured by API keys.
