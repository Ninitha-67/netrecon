from __future__ import annotations

import html
import json
from collections import Counter
from pathlib import Path

from flask import Flask, Response, jsonify
from jinja2 import Template


def _severity(score: str | float | int) -> str:
    try:
        value = float(score)
    except Exception:
        return "info"
    if value >= 9.0:
        return "critical"
    if value >= 7.0:
        return "high"
    if value >= 4.0:
        return "medium"
    if value > 0:
        return "low"
    return "info"


def _safe(value) -> str:
    return html.escape(str(value if value is not None else ""))


def _load_json(json_path: Path) -> list[dict]:
    if not json_path.exists():
        return []
    try:
        content = json_path.read_text(encoding="utf-8").strip()
        return json.loads(content) if content else []
    except Exception:
        return []


def _build_summary(data: list[dict]) -> dict:
    total_ports = len(data)
    hosts = sorted({item.get("host", "") for item in data if item.get("host")})
    total_cves = sum(len(item.get("cves", [])) for item in data)
    critical_cves = sum(
        1
        for item in data
        for cve in item.get("cves", [])
        if _severity(cve.get("score")) == "critical"
    )
    return {
        "total_ports": total_ports,
        "total_hosts": len(hosts),
        "total_cves": total_cves,
        "critical_cves": critical_cves,
    }


def _build_dashboard_stats(data: list[dict]) -> dict:
    severities = Counter(_severity(cve.get("score")) for item in data for cve in item.get("cves", []))
    services = Counter(item.get("service", "Unknown") for item in data)
    ports = Counter(str(item.get("port", "?")) for item in data)
    oses = Counter(item.get("os", "Unknown") for item in data)
    hosts = Counter(item.get("host_label") or item.get("host") or "Unknown" for item in data)
    live_shodan = sum(1 for item in data if item.get("shodan", {}).get("status") == "live")
    sent_alerts = sum(1 for item in data if item.get("alert", {}).get("status") == "sent")

    return {
        "severity_counts": [
            {"label": "Critical", "count": severities.get("critical", 0), "class": "critical"},
            {"label": "High", "count": severities.get("high", 0), "class": "high"},
            {"label": "Medium", "count": severities.get("medium", 0), "class": "medium"},
            {"label": "Low", "count": severities.get("low", 0), "class": "low"},
            {"label": "Info", "count": severities.get("info", 0), "class": "info"},
        ],
        "top_services": [{"label": label, "count": count} for label, count in services.most_common(6)],
        "top_ports": [{"label": label, "count": count} for label, count in ports.most_common(5)],
        "top_oses": [{"label": label, "count": count} for label, count in oses.most_common(4)],
        "top_hosts": [{"label": label, "count": count} for label, count in hosts.most_common(5)],
        "live_shodan": live_shodan,
        "sent_alerts": sent_alerts,
        "risk_score": round(
            min(100, (
                severities.get("critical", 0) * 25
                + severities.get("high", 0) * 15
                + severities.get("medium", 0) * 8
                + severities.get("low", 0) * 3
            )),
            1,
        ),
    }


def _render_cards(items, title, subtitle, class_name="emerald"):
    cards = []
    for item in items:
        cards.append(
            f"""
            <div class="card {class_name}">
                <h3>{_safe(item['title'])}</h3>
                <p>{_safe(item['subtitle'])}</p>
            </div>
            """
        )
    return f"""
    <section class="section">
        <div class="section-title {class_name}">{_safe(title)}</div>
        <div class="section-subtitle">{_safe(subtitle)}</div>
        <div class="grid">{''.join(cards)}</div>
    </section>
    """


HTML_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>ReconXpose Dashboard</title>
    <style>
        :root {
            --bg: #000;
            --panel: #121212;
            --text: #f2e9ff;
            --muted: #c5b7d4;
            --purple: #473c96;
            --teal: #0f5a4e;
            --orange: #91411f;
            --blue: #1c4f88;
            --green: #37670c;
            --gold: #8c5a08;
            --gray: #4a4a4a;
            --card-border: rgba(255,255,255,.25);
        }
        * { box-sizing: border-box; }
        body { margin: 0; font-family: Arial, Helvetica, sans-serif; background: var(--bg); color: var(--text); }
        .wrap { max-width: 1240px; margin: 0 auto; padding: 28px 26px 48px; }
        .hero, .section-title, .section-subtitle, .footer-note { text-align: center; }
        .hero { background: var(--purple); border: 2px solid #b3a3ff; border-radius: 22px; padding: 18px 20px; margin-bottom: 34px; }
        .hero h1 { margin: 0; font-size: clamp(2rem, 4vw, 3.5rem); }
        .hero p { margin: 8px 0 0; color: #d5d0f8; font-size: clamp(1rem, 2vw, 1.6rem); }
        .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; margin: 24px 0 34px; }
        .metric { background: var(--panel); border: 1px solid var(--card-border); border-radius: 18px; padding: 16px; min-height: 96px; }
        .metric strong { display: block; font-size: 2rem; margin-bottom: 6px; }
        .metric span { color: var(--muted); }
        .table-wrap { overflow-x: auto; margin-top: 14px; border-radius: 18px; border: 1px solid rgba(255,255,255,.12); background: #101010; }
        .table { width: 100%; border-collapse: collapse; min-width: 980px; }
        .table th, .table td { padding: 12px 14px; border-bottom: 1px solid rgba(255,255,255,.08); text-align: left; vertical-align: top; }
        .table th { background: #1c1c1c; color: #f0e7ff; position: sticky; top: 0; }
        .table tr:hover td { background: rgba(255,255,255,.03); }
        .status { display: inline-block; padding: 4px 10px; border-radius: 999px; font-size: .82rem; font-weight: 700; }
        .status.live { background: #14532d; color: #bbf7d0; }
        .status.unavailable { background: #3f3f46; color: #e4e4e7; }
        .status.error { background: #7f1d1d; color: #fecaca; }
        .status.sent { background: #14532d; color: #bbf7d0; }
        .status.not_sent { background: #3f3f46; color: #e4e4e7; }
        .status-box { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; margin-top: 14px; }
        .status-card { background: #161616; border: 1px solid rgba(255,255,255,.12); border-radius: 16px; padding: 14px; }
        .status-card h4 { margin: 0 0 8px; }
        .section { margin: 28px 0 40px; }
        .section-title { border-radius: 16px; padding: 16px 20px; font-weight: 800; font-size: 1.4rem; border: 1px solid rgba(255,255,255,.28); margin-bottom: 10px; }
        .section-title.teal { background: linear-gradient(180deg, #105f4e, #0c4d42); }
        .section-title.orange { background: linear-gradient(180deg, #94421f, #763317); }
        .section-title.blue { background: linear-gradient(180deg, #1d558e, #164170); }
        .section-title.green { background: linear-gradient(180deg, #3b6710, #2f530b); }
        .section-title.gold { background: linear-gradient(180deg, #8d5d0b, #6f4807); }
        .section-subtitle { color: var(--muted); margin: 0 0 16px; font-size: 1rem; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; }
        .card { border-radius: 18px; padding: 18px 16px; border: 1px solid rgba(255,255,255,.28); min-height: 118px; }
        .card h3 { margin: 0 0 10px; font-size: 1.35rem; color: #e6dfeb; }
        .card p { margin: 0; color: #d6b7ac; line-height: 1.45; }
        .card.emerald { background: linear-gradient(180deg, #0d5c4f, #0f4d43); }
        .card.orange { background: linear-gradient(180deg, #8d3f1d, #6f3016); }
        .card.gray { background: linear-gradient(180deg, #565656, #404040); }
        .pipeline { display: flex; flex-wrap: wrap; justify-content: center; align-items: center; gap: 10px; margin: 18px 0 10px; }
        .pipe-card { padding: 18px 22px; border-radius: 16px; min-width: 210px; text-align: center; font-weight: 800; border: 1px solid rgba(255,255,255,.25); }
        .pipe-card.purple { background: #5146a0; }
        .pipe-card.teal { background: #115d4f; }
        .pipe-card.amber { background: #8f4b1d; }
        .pipe-card.rust { background: #6f301a; }
        .pipe-card.gold { background: #8c5b0b; }
        .arrow { color: #aaa; font-size: 2rem; font-weight: 700; }
        .scan-results { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; }
        .scan-card { background: #141414; border: 1px solid rgba(255,255,255,.15); border-radius: 18px; padding: 16px; }
        .scan-card header { display: flex; justify-content: space-between; gap: 8px; align-items: baseline; margin-bottom: 10px; }
        .scan-card h3 { margin: 0; font-size: 1.1rem; }
        .scan-card header span { color: #9ad7ff; font-weight: 700; }
        .scan-card p { color: #d7d1de; line-height: 1.45; }
        .cve-list { margin-top: 10px; display: grid; gap: 10px; }
        .cve { border-radius: 14px; padding: 12px; border-left: 6px solid; background: rgba(255,255,255,.03); }
        .cve.critical { border-left-color: #ff4d5d; }
        .cve.high { border-left-color: #ff8b4d; }
        .cve.medium { border-left-color: #ffc94d; }
        .cve.low { border-left-color: #59d48f; }
        .cve.info { border-left-color: #7aa7ff; }
        .cve strong { display: block; margin-bottom: 4px; }
        .cve span { color: #f5d7a3; font-size: .95rem; }
        .cve p, .empty { margin: 8px 0 0; color: #c7c0ce; }
        .alert-box, .demo-box { background: #161616; border: 1px solid rgba(255,255,255,.15); border-radius: 18px; padding: 16px; margin-top: 16px; }
        .alert-box h3, .demo-box h3 { margin-top: 0; }
        .pill { display: inline-block; padding: 4px 10px; border-radius: 999px; background: #2a2a2a; margin-right: 8px; margin-bottom: 8px; }
        .pill.live { background: #14532d; color: #bbf7d0; }
        .pill.unavailable { background: #3f3f46; color: #e4e4e7; }
        .pill.error { background: #7f1d1d; color: #fecaca; }
        .pill.sent { background: #14532d; color: #bbf7d0; }
        .footer-note { color: var(--muted); margin-top: 24px; font-size: .95rem; }
        @media (max-width: 700px) {
            .wrap { padding: 18px 14px 40px; }
            .hero h1 { font-size: 2rem; }
            .arrow { display: none; }
            .pipe-card { width: 100%; }
        }
    </style>
</head>
<body>
    <div class="wrap">
        <header class="hero">
            <h1>ReconXpose</h1>
            <p>Advanced network vulnerability intelligence platform</p>
        </header>

        <section class="metrics">
            <div class="metric"><strong>{{ summary.total_hosts }}</strong><span>Unique hosts</span></div>
            <div class="metric"><strong>{{ summary.total_ports }}</strong><span>Ports/services discovered</span></div>
            <div class="metric"><strong>{{ summary.total_cves }}</strong><span>Total CVEs found</span></div>
            <div class="metric"><strong>{{ summary.critical_cves }}</strong><span>Critical CVEs</span></div>
        </section>

        {{ core_section|safe }}
        {{ new_section|safe }}

        <section class="section">
            <div class="section-title blue">Full ReconXpose pipeline</div>
            <div class="pipeline">
                <div class="pipe-card purple">Input targets</div>
                <div class="arrow">→</div>
                <div class="pipe-card teal">Host discovery</div>
                <div class="arrow">→</div>
                <div class="pipe-card teal">Port + OS scan</div>
                <div class="arrow">→</div>
                <div class="pipe-card teal">Service enumeration</div>
                <div class="arrow">↓</div>
                <div class="pipe-card amber">CVE + Shodan lookup</div>
                <div class="arrow">←</div>
                <div class="pipe-card rust">Alert engine</div>
                <div class="arrow">←</div>
                <div class="pipe-card gold">Report / Dashboard</div>
            </div>
        </section>

        <section class="section">
            <div class="section-title teal">Integration status</div>
            <div class="status-box">
                <div class="status-card"><h4>NVD</h4><span class="status {{ 'live' if summary.total_cves else 'unavailable' }}">{{ 'live' if summary.total_cves else 'unavailable' }}</span></div>
                <div class="status-card"><h4>Shodan</h4><span class="status {{ 'live' if data and data[0].shodan.status == 'live' else data[0].shodan.status if data else 'unavailable' }}">{{ data[0].shodan.status if data else 'unavailable' }}</span></div>
                <div class="status-card"><h4>Email alerts</h4><span class="status {{ data[0].alert.status if data else 'not_sent' }}">{{ data[0].alert.status if data else 'not_sent' }}</span></div>
            </div>
        </section>

        <section class="section">
            <div class="section-title green">Why ReconXpose is unique vs existing tools</div>
            <div class="grid">
                {% for item in uniqueness %}
                <div class="card gray"><h3>{{ item.title }}</h3><p>{{ item.subtitle }}</p></div>
                {% endfor %}
            </div>
        </section>

        <section class="section">
            <div class="section-title gold">Updated technology stack</div>
            <div class="grid">
                {% for item in stack %}
                <div class="card orange"><h3>{{ item.title }}</h3><p>{{ item.subtitle }}</p></div>
                {% endfor %}
            </div>
        </section>

        <section class="section">
            <div class="section-title teal">Scan results</div>
            <div class="table-wrap">
                <table class="table">
                    <thead>
                        <tr>
                            <th>Host</th>
                            <th>Port</th>
                            <th>Service</th>
                            <th>Product</th>
                            <th>Version</th>
                            <th>OS</th>
                            <th>CVEs</th>
                            <th>Shodan</th>
                            <th>Email</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for item in data %}
                        <tr>
                            <td>{{ item.host_label or item.host }}</td>
                            <td>{{ item.port }}/{{ item.proto }}</td>
                            <td>{{ item.service }}</td>
                            <td>{{ item.product }}</td>
                            <td>{{ item.version }}</td>
                            <td>{{ item.os }}</td>
                            <td>
                                {% if item.cves %}
                                    {% for cve in item.cves[:2] %}
                                        <div class="cve {{ cve.severity }}"><strong>{{ cve.id }}</strong><span>Score {{ cve.score }}</span></div>
                                    {% endfor %}
                                {% else %}
                                    <span class="status unavailable">No CVEs</span>
                                {% endif %}
                            </td>
                            <td>
                                <span class="status {{ item.shodan.status }}">{{ item.shodan.status }}</span>
                                <div style="margin-top:8px">{{ item.shodan.summary }}</div>
                                <div>{{ item.shodan.exposure }}</div>
                            </td>
                            <td>
                                <span class="status {{ item.alert.status }}">{{ item.alert.status }}</span>
                                <div style="margin-top:8px">{{ item.alert.message }}</div>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </section>

        <div class="footer-note">Generated from {{ json_name }}.</div>
    </div>
</body>
</html>
"""


DASHBOARD_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>ReconXpose Dashboard</title>
    <style>
        :root {
            --bg: #f4f7fb;
            --panel: #ffffff;
            --ink: #162033;
            --muted: #64748b;
            --line: #d9e2ef;
            --blue: #1d4ed8;
            --green: #047857;
            --orange: #c2410c;
            --red: #b91c1c;
            --purple: #5b21b6;
            --shadow: 0 18px 50px rgba(15, 23, 42, .08);
        }
        * { box-sizing: border-box; }
        body { margin: 0; font-family: Arial, Helvetica, sans-serif; background: var(--bg); color: var(--ink); }
        .shell { display: grid; grid-template-columns: 280px 1fr; min-height: 100vh; }
        .sidebar { background: linear-gradient(180deg, #0f172a, #111827); color: #e5eefb; padding: 24px; }
        .brand { font-size: 1.8rem; font-weight: 900; margin-bottom: 6px; }
        .brand-sub { color: #9fb2d1; font-size: .95rem; margin-bottom: 22px; }
        .navcard { background: rgba(255,255,255,.06); border: 1px solid rgba(255,255,255,.08); border-radius: 16px; padding: 14px; margin-bottom: 14px; }
        .navcard h4 { margin: 0 0 8px; }
        .navcard p { margin: 0; color: #b6c6e0; font-size: .92rem; line-height: 1.4; }
        .content { padding: 22px; }
        .topbar { display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 18px; }
        .hero { background: var(--panel); border-radius: 20px; padding: 18px 20px; box-shadow: var(--shadow); border: 1px solid var(--line); }
        .hero h1 { margin: 0; font-size: 1.8rem; }
        .hero p { margin: 8px 0 0; color: var(--muted); }
        .toolbar { display: flex; gap: 10px; flex-wrap: wrap; }
        .input, .select { border: 1px solid var(--line); background: #fff; border-radius: 12px; padding: 10px 12px; min-width: 180px; }
        .btn { border: 0; background: var(--blue); color: #fff; border-radius: 12px; padding: 10px 14px; font-weight: 700; cursor: pointer; }
        .btn.secondary { background: #334155; }
        .btn.green { background: var(--green); }
        .grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 14px; margin-top: 18px; }
        .metric { background: var(--panel); border: 1px solid var(--line); border-radius: 18px; padding: 16px; box-shadow: var(--shadow); }
        .metric .k { font-size: 2rem; font-weight: 900; margin-bottom: 4px; }
        .metric .l { color: var(--muted); }
        .metric .s { font-size: .82rem; margin-top: 8px; color: var(--muted); }
        .meter { background: #e2e8f0; border-radius: 999px; height: 14px; overflow: hidden; margin-top: 12px; }
        .meter-fill { height: 100%; border-radius: 999px; background: linear-gradient(90deg, #22c55e, #eab308, #f97316, #ef4444); }
        .panel { margin-top: 18px; background: var(--panel); border-radius: 20px; border: 1px solid var(--line); box-shadow: var(--shadow); overflow: hidden; }
        .panel-h { padding: 16px 18px; border-bottom: 1px solid var(--line); display: flex; justify-content: space-between; align-items: center; gap: 12px; }
        .panel-h h2 { margin: 0; font-size: 1.1rem; }
        .panel-h span { color: var(--muted); font-size: .92rem; }
        .filters { padding: 14px 18px; display: flex; flex-wrap: wrap; gap: 10px; border-bottom: 1px solid var(--line); }
        .pill { padding: 6px 10px; border-radius: 999px; font-size: .82rem; font-weight: 700; display: inline-block; }
        .pill.live { background: #dcfce7; color: #166534; }
        .pill.unavailable { background: #e5e7eb; color: #374151; }
        .pill.error { background: #fee2e2; color: #991b1b; }
        .pill.sent { background: #dcfce7; color: #166534; }
        .pill.not_sent { background: #e5e7eb; color: #374151; }
        .table-wrap { overflow-x: auto; }
        .table { width: 100%; border-collapse: collapse; min-width: 1200px; }
        .table th, .table td { padding: 12px 14px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; }
        .table th { background: #f8fafc; color: #334155; position: sticky; top: 0; }
        .table tr:hover td { background: #f8fbff; }
        .stack { display: grid; grid-template-columns: 1.2fr .8fr; gap: 14px; margin-top: 18px; }
        .mini { background: var(--panel); border: 1px solid var(--line); border-radius: 18px; box-shadow: var(--shadow); padding: 16px; }
        .mini h3 { margin: 0 0 12px; }
        .detail-card { background: linear-gradient(180deg, #0f172a, #111827); color: #e5eefb; border-radius: 18px; padding: 16px; box-shadow: var(--shadow); }
        .detail-card h3 { margin: 0 0 10px; }
        .detail-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }
        .detail-grid div { background: rgba(255,255,255,.06); border-radius: 12px; padding: 10px; }
        .detail-grid span { display: block; color: #9fb2d1; font-size: .82rem; margin-bottom: 3px; }
        .bars { display: grid; gap: 10px; }
        .bar-row { display: grid; grid-template-columns: 120px 1fr 40px; gap: 10px; align-items: center; }
        .bar-track { height: 12px; background: #e2e8f0; border-radius: 999px; overflow: hidden; }
        .bar-fill { height: 100%; border-radius: 999px; }
        .bar-fill.critical { background: #ef4444; }
        .bar-fill.high { background: #f97316; }
        .bar-fill.medium { background: #eab308; }
        .bar-fill.low { background: #22c55e; }
        .bar-fill.info { background: #3b82f6; }
        .scanline { display: flex; gap: 8px; flex-wrap: wrap; }
        .cve { display: inline-flex; gap: 8px; align-items: center; padding: 7px 10px; border-radius: 10px; margin: 4px 6px 0 0; border: 1px solid var(--line); background: #fff; }
        .sev-critical { color: var(--red); }
        .sev-high { color: var(--orange); }
        .sev-medium { color: #b45309; }
        .sev-low { color: var(--green); }
        .sev-info { color: var(--blue); }
        .footer { color: var(--muted); margin-top: 18px; font-size: .92rem; }
        .drawer-backdrop { position: fixed; inset: 0; background: rgba(15,23,42,.55); display: none; align-items: center; justify-content: center; z-index: 50; padding: 18px; }
        .drawer { width: min(820px, 100%); background: #fff; border-radius: 22px; box-shadow: var(--shadow); overflow: hidden; }
        .drawer-head { padding: 16px 18px; background: linear-gradient(90deg, #0f172a, #1e293b); color: #fff; display: flex; justify-content: space-between; align-items: center; gap: 12px; }
        .drawer-body { padding: 18px; display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
        .drawer-body .box { background: #f8fafc; border: 1px solid var(--line); border-radius: 16px; padding: 12px; }
        .drawer-body .box span { display: block; color: var(--muted); font-size: .82rem; margin-bottom: 4px; }
        .close-btn { background: rgba(255,255,255,.12); color: #fff; border: 0; border-radius: 999px; padding: 8px 12px; cursor: pointer; }
        .chart-card { background: var(--panel); border: 1px solid var(--line); border-radius: 18px; box-shadow: var(--shadow); padding: 16px; }
        .donut-wrap { display: grid; grid-template-columns: 220px 1fr; gap: 18px; align-items: center; }
        .donut { width: 180px; aspect-ratio: 1; border-radius: 50%; background: conic-gradient(#ef4444 0 25%, #f97316 25% 45%, #eab308 45% 65%, #22c55e 65% 85%, #3b82f6 85% 100%); position: relative; margin: 0 auto; }
        .donut::after { content: ''; position: absolute; inset: 28px; border-radius: 50%; background: #fff; }
        .donut-center { position: absolute; inset: 0; display: grid; place-items: center; font-weight: 900; font-size: 1.5rem; color: #0f172a; }
        .legend { display: grid; gap: 8px; }
        .legend-row { display: flex; justify-content: space-between; gap: 10px; background: #f8fafc; border: 1px solid var(--line); border-radius: 12px; padding: 10px 12px; }
        @media (max-width: 1100px) {
            .shell { grid-template-columns: 1fr; }
            .sidebar { order: 2; }
            .grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
            .stack { grid-template-columns: 1fr; }
        }
        @media (max-width: 640px) {
            .content { padding: 14px; }
            .grid { grid-template-columns: 1fr; }
            .topbar { flex-direction: column; align-items: stretch; }
            .toolbar { width: 100%; }
            .input, .select { min-width: 0; width: 100%; }
        }
    </style>
</head>
<body>
    <div class="shell">
        <aside class="sidebar">
            <div class="brand">ReconXpose</div>
            <div class="brand-sub">Interactive reconnaissance dashboard</div>
            <div class="navcard">
                <h4>Live pipeline</h4>
                <p>Scan targets, detect OS, enrich CVEs, and review Shodan and email status from one view.</p>
            </div>
            <div class="navcard">
                <h4>Quick actions</h4>
                <p>Use the browser search box to filter hosts, ports, and services during the demo.</p>
            </div>
            <div class="navcard">
                <h4>Outputs</h4>
                <p>HTML report, JSON data, live status cards, and interactive tables.</p>
            </div>
        </aside>
        <main class="content">
            <div class="topbar">
                <div class="hero">
                    <h1>ReconXpose Dashboard</h1>
                    <p>Interactive view of scan results, Shodan status, CVEs, and email alert state.</p>
                </div>
                <div class="toolbar">
                    <input id="searchBox" class="input" type="text" placeholder="Search host, service, port...">
                    <select id="statusFilter" class="select">
                        <option value="all">All status</option>
                        <option value="live">Live Shodan</option>
                        <option value="unavailable">Unavailable</option>
                        <option value="sent">Email sent</option>
                        <option value="not_sent">No alert</option>
                        <option value="error">Error</option>
                    </select>
                    <input id="scanTarget" class="input" type="text" placeholder="New scan target...">
                    <button class="btn green" onclick="runNewScan()">Run new scan</button>
                    <button class="btn" onclick="window.location.reload()">Refresh</button>
                    <button class="btn secondary" onclick="document.getElementById('searchBox').value=''; document.getElementById('statusFilter').value='all'; filterRows();">Clear</button>
                </div>
            </div>

            <section class="grid">
                <div class="metric"><div class="k">{{ summary.total_hosts }}</div><div class="l">Unique hosts</div><div class="s">Across all scanned targets</div></div>
                <div class="metric"><div class="k">{{ summary.total_ports }}</div><div class="l">Ports/services</div><div class="s">Discovered open endpoints</div></div>
                <div class="metric"><div class="k">{{ summary.total_cves }}</div><div class="l">Total CVEs</div><div class="s">NVD enrichment results</div></div>
                <div class="metric"><div class="k">{{ summary.critical_cves }}</div><div class="l">Critical CVEs</div><div class="s">Potential alert triggers</div></div>
            </section>

            <section class="panel">
                <div class="panel-h"><h2>Risk overview</h2><span>{{ dashboard.risk_score }}/100</span></div>
                <div style="padding:16px 18px 20px">
                    <div class="meter"><div class="meter-fill" style="width: {{ dashboard.risk_score }}%"></div></div>
                    <div style="margin-top:10px; color: var(--muted)">Overall risk is derived from severity distribution and alert pressure.</div>
                </div>
            </section>

            <section class="panel">
                <div class="panel-h"><h2>Integration status</h2><span>Live backend states</span></div>
                <div class="filters">
                    <span class="pill {{ 'live' if summary.total_cves else 'unavailable' }}">NVD: {{ 'live' if summary.total_cves else 'unavailable' }}</span>
                    <span class="pill {{ data[0].shodan.status if data else 'unavailable' }}">Shodan: {{ data[0].shodan.status if data else 'unavailable' }}</span>
                    <span class="pill {{ data[0].alert.status if data else 'not_sent' }}">Email: {{ data[0].alert.status if data else 'not_sent' }}</span>
                    <span class="pill live">Live Shodan hits: {{ dashboard.live_shodan }}</span>
                    <span class="pill sent">Emails sent: {{ dashboard.sent_alerts }}</span>
                </div>
            </section>

            <div class="stack">
                <section class="chart-card">
                    <div class="panel-h" style="padding:0 0 12px;border:0"><h2>Severity donut</h2><span>Live CVE mix</span></div>
                    <div class="donut-wrap">
                        <div style="position:relative;width:180px;height:180px;margin:0 auto">
                            <div class="donut"></div>
                            <div class="donut-center">{{ summary.total_cves }}</div>
                        </div>
                        <div class="legend">
                            {% for sev in dashboard.severity_counts %}
                            <div class="legend-row"><span>{{ sev.label }}</span><strong>{{ sev.count }}</strong></div>
                            {% endfor %}
                        </div>
                    </div>
                </section>
                <section class="chart-card">
                    <div class="panel-h" style="padding:0 0 12px;border:0"><h2>Top ports</h2><span>Most exposed services</span></div>
                    <div class="bars">
                        {% for item in dashboard.top_ports %}
                        <div class="bar-row">
                            <div>{{ item.label }}</div>
                            <div class="bar-track"><div class="bar-fill info" style="width: {{ (item.count * 100 / (dashboard.top_ports[0].count or 1)) if dashboard.top_ports else 0 }}%"></div></div>
                            <div>{{ item.count }}</div>
                        </div>
                        {% endfor %}
                    </div>
                </section>
            </div>

            <div class="stack">
                <section class="mini">
                    <h3>CVE severity mix</h3>
                    <div class="bars">
                        {% for sev in dashboard.severity_counts %}
                        <div class="bar-row">
                            <div>{{ sev.label }}</div>
                            <div class="bar-track"><div class="bar-fill {{ sev.class }}" style="width: {{ (sev.count * 100 / (summary.total_cves or 1)) if summary.total_cves else 0 }}%"></div></div>
                            <div>{{ sev.count }}</div>
                        </div>
                        {% endfor %}
                    </div>
                </section>
                <section class="mini">
                    <h3>Top signals</h3>
                    <div class="scanline">
                        {% for item in dashboard.top_hosts %}<span class="pill unavailable">{{ item.label }}: {{ item.count }}</span>{% endfor %}
                    </div>
                    <div style="margin-top:12px" class="scanline">
                        {% for item in dashboard.top_services %}<span class="pill live">{{ item.label }}: {{ item.count }}</span>{% endfor %}
                    </div>
                </section>
            </div>

            <section class="panel">
                <div class="panel-h"><h2>Selected host detail</h2><span>Click a row in the results table</span></div>
                <div style="padding:16px 18px">
                    <div id="detailCard" class="detail-card">
                        <h3>Awaiting selection</h3>
                        <p>Click any row in the table above to inspect host, service, OS, Shodan, and alert details.</p>
                    </div>
                </div>
            </section>

            <section class="panel">
                <div class="panel-h"><h2>Results table</h2><span>Hover rows for emphasis</span></div>
                <div class="table-wrap">
                    <table class="table" id="resultsTable">
                        <thead>
                            <tr>
                                <th>Host</th><th>Port</th><th>Service</th><th>Product</th><th>Version</th><th>OS</th><th>CVEs</th><th>Shodan</th><th>Email</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for item in data %}
                            <tr data-search="{{ (item.host_label ~ ' ' ~ item.host ~ ' ' ~ item.port ~ ' ' ~ item.service ~ ' ' ~ item.product ~ ' ' ~ item.version ~ ' ' ~ item.os)|lower }}" data-status="{{ item.shodan.status }} {{ item.alert.status }}">
                                <td>{{ item.host_label or item.host }}</td>
                                <td>{{ item.port }}/{{ item.proto }}</td>
                                <td>{{ item.service }}</td>
                                <td>{{ item.product }}</td>
                                <td>{{ item.version }}</td>
                                <td>{{ item.os }}</td>
                                <td>
                                    {% if item.cves %}
                                        {% for cve in item.cves[:3] %}
                                            <div class="cve"><span class="sev-{{ cve.severity }}">{{ cve.id }}</span><span>{{ cve.score }}</span></div>
                                        {% endfor %}
                                    {% else %}
                                        <span class="pill unavailable">No CVEs</span>
                                    {% endif %}
                                </td>
                                <td>
                                    <span class="pill {{ item.shodan.status }}">{{ item.shodan.status }}</span>
                                    <div style="margin-top:8px">{{ item.shodan.summary }}</div>
                                </td>
                                <td>
                                    <span class="pill {{ item.alert.status }}">{{ item.alert.status }}</span>
                                    <div style="margin-top:8px">{{ item.alert.message }}</div>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </section>

            <section class="stack">
                <div class="mini">
                    <h3>Shodan details</h3>
                    {% for item in data[:4] %}
                        <div class="cve"><strong>{{ item.host_label or item.host }}</strong><span>{{ item.shodan.exposure }}</span></div>
                    {% endfor %}
                </div>
                <div class="mini">
                    <h3>Email summary</h3>
                    {% for item in data[:4] %}
                        <div class="cve"><strong>{{ item.host_label or item.host }}</strong><span>{{ item.alert.message }}</span></div>
                    {% endfor %}
                </div>
            </section>

            <div id="drawerBackdrop" class="drawer-backdrop" onclick="closeDrawer(event)">
                <div class="drawer" onclick="event.stopPropagation()">
                    <div class="drawer-head">
                        <div>
                            <div style="font-size:1.1rem;font-weight:800">Host details</div>
                            <div id="drawerTitle" style="font-size:.9rem;color:#cbd5e1">Select a row to inspect</div>
                        </div>
                        <button class="close-btn" onclick="hideDrawer()">Close</button>
                    </div>
                    <div class="drawer-body" id="drawerBody">
                        <div class="box"><span>Tip</span>Click a row in the results table to open a detailed drawer.</div>
                    </div>
                </div>
            </div>

            <div class="footer">Generated from {{ json_name }}.</div>
        </main>
    </div>
    <script>
        const searchBox = document.getElementById('searchBox');
        const statusFilter = document.getElementById('statusFilter');
        const scanTarget = document.getElementById('scanTarget');
        const rows = Array.from(document.querySelectorAll('#resultsTable tbody tr'));
        const detailCard = document.getElementById('detailCard');
        const drawerBackdrop = document.getElementById('drawerBackdrop');
        const drawerTitle = document.getElementById('drawerTitle');
        const drawerBody = document.getElementById('drawerBody');

        function filterRows() {
            const q = searchBox.value.trim().toLowerCase();
            const s = statusFilter.value;
            rows.forEach((row) => {
                const haystack = row.dataset.search || '';
                const status = row.dataset.status || '';
                const matchesText = !q || haystack.includes(q);
                const matchesStatus = s === 'all' || status.includes(s);
                row.style.display = matchesText && matchesStatus ? '' : 'none';
            });
        }

        function updateDetail(row) {
            const host = row.children[0].innerText;
            const port = row.children[1].innerText;
            const service = row.children[2].innerText;
            const product = row.children[3].innerText;
            const version = row.children[4].innerText;
            const os = row.children[5].innerText;
            const shodan = row.children[7].innerText.replace(/\\s+/g, ' ').trim();
            const email = row.children[8].innerText.replace(/\\s+/g, ' ').trim();
            detailCard.innerHTML = `
                <h3>${host}</h3>
                <div class="detail-grid">
                    <div><span>Port</span>${port}</div>
                    <div><span>Service</span>${service}</div>
                    <div><span>Product</span>${product}</div>
                    <div><span>Version</span>${version}</div>
                    <div><span>OS</span>${os}</div>
                    <div><span>Status</span>${email}</div>
                </div>
                <p style="margin-top:12px"><strong>Shodan:</strong> ${shodan}</p>
            `;

            drawerTitle.textContent = host;
            drawerBody.innerHTML = `
                <div class="box"><span>Host</span>${host}</div>
                <div class="box"><span>Port</span>${port}</div>
                <div class="box"><span>Service</span>${service}</div>
                <div class="box"><span>Product</span>${product}</div>
                <div class="box"><span>Version</span>${version}</div>
                <div class="box"><span>OS</span>${os}</div>
                <div class="box"><span>Shodan</span>${shodan}</div>
                <div class="box"><span>Email</span>${email}</div>
            `;
            drawerBackdrop.style.display = 'flex';
        }

        function hideDrawer() {
            drawerBackdrop.style.display = 'none';
        }

        function closeDrawer(event) {
            if (event.target === drawerBackdrop) hideDrawer();
        }

        async function runNewScan() {
            const target = scanTarget.value.trim();
            if (!target) {
                alert('Enter a target to scan');
                return;
            }
            const button = Array.from(document.querySelectorAll('.btn.green'))[0];
            button.disabled = true;
            button.textContent = 'Scanning...';
            try {
                const response = await fetch('/run-scan', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({target}),
                });
                if (!response.ok) throw new Error('Scan failed');
                window.location.reload();
            } catch (err) {
                alert(err.message || 'Scan failed');
            } finally {
                button.disabled = false;
                button.textContent = 'Run new scan';
            }
        }

        searchBox.addEventListener('input', filterRows);
        statusFilter.addEventListener('change', filterRows);
        rows.forEach((row) => row.addEventListener('click', () => updateDetail(row)));
    </script>
</body>
</html>
"""


def generate_html_report(json_file, output_file="report.html"):
    json_path = Path(json_file)
    output_path = Path(output_file)
    data = _load_json(json_path)
    if not data:
        print("[!] JSON file empty. Skipping HTML report.")
        return

    for item in data:
        item["cves"] = [dict(cve, severity=_severity(cve.get("score"))) for cve in item.get("cves", [])]

    summary = _build_summary(data)
    core_section = _render_cards(
        [
            {"title": "Host discovery", "subtitle": "Nmap ping sweep"},
            {"title": "Port scanner", "subtitle": "TCP/UDP, banners"},
            {"title": "CVE lookup", "subtitle": "NVD API integration"},
            {"title": "JSON report gen.", "subtitle": "Structured output"},
        ],
        "Core engine — carried from ReconXpose (100% complete)",
        "Core scanning and enrichment pipeline",
        "teal",
    )
    new_section = _render_cards(
        [
            {"title": "HTML report export", "subtitle": "Browser-readable output with severity colour codes"},
            {"title": "Multi-target scanning", "subtitle": "Batch IP / subnet input, parallel scan threads"},
            {"title": "OS detection module", "subtitle": "Nmap OS fingerprinting, OS-specific CVE filter"},
            {"title": "Web dashboard", "subtitle": "Flask UI to visualise scan results live"},
            {"title": "Shodan API integration", "subtitle": "Passive recon layer for internet-exposed hosts"},
            {"title": "Critical CVE alerts", "subtitle": "Email alert when CVSS score exceeds 7.0"},
        ],
        "6 new modules — what makes ReconXpose unique",
        "Roadmap features shown in the architecture mockup",
        "orange",
    )

    html_doc = Template(HTML_TEMPLATE).render(
        data=data,
        summary=summary,
        core_section=core_section,
        new_section=new_section,
        uniqueness=[
            {"title": "vs Nmap alone", "subtitle": "Adds CVE lookup + HTML reports + alerts in one pipeline"},
            {"title": "vs Shodan alone", "subtitle": "Adds active scanning + real-time OS detect + dashboard view"},
            {"title": "vs OpenVAS", "subtitle": "Lightweight Python tool, no heavy setup, custom email + Shodan layer"},
        ],
        stack=[
            {"title": "Python 3", "subtitle": "Core language"},
            {"title": "Nmap / python-nmap", "subtitle": "Scanning engine"},
            {"title": "Flask", "subtitle": "Web dashboard"},
            {"title": "Shodan API", "subtitle": "Passive recon"},
            {"title": "NVD / CVE API", "subtitle": "Vulnerability data"},
        ],
        json_name=json_path.name,
    )

    output_path.write_text(html_doc, encoding="utf-8")
    print(f"[OK] HTML report saved as {output_path}")


def render_dashboard_html(json_path: Path, report_path: Path) -> str:
    data = _load_json(json_path)
    if not data and report_path.exists():
        try:
            return report_path.read_text(encoding="utf-8")
        except Exception:
            return "<h1>ReconXpose Dashboard</h1><p>No report data yet. Run a scan first.</p>"
    if not data:
        return "<h1>ReconXpose Dashboard</h1><p>No report data yet. Run a scan first.</p>"

    for item in data:
        item["cves"] = [dict(cve, severity=_severity(cve.get("score"))) for cve in item.get("cves", [])]

    summary = _build_summary(data)
    dashboard = _build_dashboard_stats(data)
    return Template(DASHBOARD_TEMPLATE).render(
        data=data,
        summary=summary,
        dashboard=dashboard,
        json_name=json_path.name,
    )


def create_app(json_path: Path, report_path: Path, run_scan_callback=None) -> Flask:
    app = Flask(__name__)

    @app.route("/")
    def index():
        return Response(render_dashboard_html(json_path, report_path), mimetype="text/html")

    @app.route("/dashboard")
    def dashboard():
        return Response(render_dashboard_html(json_path, report_path), mimetype="text/html")

    @app.route("/api/report")
    def api_report():
        return jsonify(_load_json(json_path))

    @app.route("/run-scan", methods=["POST"])
    def run_scan():
        if run_scan_callback is None:
            return jsonify({"error": "scan callback unavailable"}), 400
        from flask import request

        data = request.get_json(silent=True) or {}
        target = str(data.get("target", "")).strip()
        if not target:
            return jsonify({"error": "target is required"}), 400
        ok = run_scan_callback(target)
        if not ok:
            return jsonify({"error": "scan failed"}), 500
        return jsonify({"status": "ok", "target": target})

    return app
