#!/usr/bin/env python3
"""
secscan-dash — lightweight HTML dashboard server.
Serves real-time scanner reports via a simple HTTP page.
"""
import json
import os
import time
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler

API_URL = "http://127.0.0.1:9090"
REPORT_DIR = Path("/var/lib/secscan/reports")
HOSTNAME = os.uname().nodename

def fetch_json(url):
    import urllib.request
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read())
    except: return None

def get_latest():
    d = fetch_json(f"{API_URL}/report/latest")
    if d and d.get("success"): return d["data"]
    return None

def get_reports():
    if not REPORT_DIR.exists(): return []
    out = []
    for r in sorted(REPORT_DIR.glob("scan-*.json"), reverse=True)[:20]:
        try:
            d = json.loads(r.read_text())
            out.append({"file": r.name, "date": d.get("timestamp","")[:19],
                        "total": d.get("total_findings",0),
                        "crit": d.get("criticals",0), "high": d.get("highs",0),
                        "med": d.get("mediums",0)})
        except: out.append({"file": r.name, "date":"", "total":0})
    return out

def run_scan():
    import urllib.request
    try:
        req = urllib.request.Request(f"{API_URL}/scan", method="POST")
        with urllib.request.urlopen(req, timeout=120) as r:
            return json.loads(r.read())
    except Exception as e: return {"success": False, "error": str(e)}

# Read template HTML
TEMPLATE = (Path(__file__).parent / "dash.html").read_text()

class DashHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/" or p == "":
            self.send_dash()
        elif p == "/health":
            self.send_json({"status":"ok","service":"secscan-dash"})
        elif p == "/reports":
            self.send_json(get_reports())
        else:
            self.send_error(404)
    def do_POST(self):
        if self.path == "/scan":
            self.send_json(run_scan())
        else:
            self.send_error(404)

    def send_json(self, data):
        b = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type","application/json")
        self.send_header("Access-Control-Allow-Origin","*")
        self.send_header("Content-Length",str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def send_dash(self):
        report = get_latest()
        reports = get_reports()

        summary_html = ""
        findings_html = ""

        if report:
            s = report
            total = s["total_findings"]
            crit, high, med, low = s["criticals"], s["highs"], s["mediums"], s["lows"]
            ts = s.get("timestamp","")[:19].replace("T"," ")
            info = total - crit - high - med - low

            # Severity bar widths
            cw = (crit/max(total,1))*100
            hw = (high/max(total,1))*100
            mw = (med/max(total,1))*100
            lw = (low/max(total,1))*100
            iw = (info/max(total,1))*100

            summary_html = f"""
            <div class="stats-grid">
              <div class="stat-card critical"><div class="number">{crit}</div><div class="label">Critical</div></div>
              <div class="stat-card high"><div class="number">{high}</div><div class="label">High</div></div>
              <div class="stat-card medium"><div class="number">{med}</div><div class="label">Medium</div></div>
              <div class="stat-card low"><div class="number">{low}</div><div class="label">Low</div></div>
              <div class="stat-card info"><div class="number">{total}</div><div class="label">Total</div></div>
              <div class="stat-card"><div class="number" style="font-size:1rem;">{ts}</div><div class="label">Last Scan</div></div>
            </div>
            <div class="severity-bar">
              <div class="segment" style="width:{cw:.1f}%;background:#f85149;"></div>
              <div class="segment" style="width:{hw:.1f}%;background:#d29922;"></div>
              <div class="segment" style="width:{mw:.1f}%;background:#dbb700;"></div>
              <div class="segment" style="width:{lw:.1f}%;background:#3fb950;"></div>
              <div class="segment" style="width:{iw:.1f}%;background:#58a6ff;"></div>
            </div>
            """
            findings_html = '<div class="section-title">🔍 Findings</div><div class="finding-list">'
            for f in s["findings"]:
                sev = f["severity"].lower()
                cat = f["category"]
                title = f["title"]
                desc = f["description"]
                fix = f.get("remediation","")
                findings_html += f'''
                <details class="finding-details">
                  <summary><span class="sev-tag sev-{sev}">{f["severity"]}</span> <span class="cat-tag">[{cat}]</span> {title}</summary>
                  <p class="desc">{desc}</p>
                  <p class="fix">&#8594; {fix}</p>
                </details>
                '''
            findings_html += "</div>"
        else:
            summary_html = '<div class="empty">No scan reports yet. Click "Run Scan" to start.</div>'

        hist_html = ""
        if reports:
            rows = ""
            for r in reports[:10]:
                dots = ""
                if r.get("crit",0)>0: dots+='<span class="dot-red"></span> '
                if r.get("high",0)>0: dots+='<span class="dot-yellow"></span> '
                if r.get("med",0)>0: dots+='<span class="dot-yellow"></span> '
                rows += f"<tr><td>{r['file']}</td><td>{dots}</td><td>{r.get('total',0)}</td><td>{r.get('crit',0)}/{r.get('high',0)}/{r.get('med',0)}</td></tr>"
            hist_html = f"""
            <div class="section-title">📊 Scan History</div>
            <table class="report-table">
              <thead><tr><th>Report</th><th>Sev</th><th>Total</th><th>C/H/M</th></tr></thead>
              <tbody>{rows}</tbody>
            </table>
            """

        html = TEMPLATE.replace("__HOSTNAME__", HOSTNAME)
        html = html.replace("__SUMMARY__", summary_html)
        html = html.replace("__FINDINGS__", findings_html)
        html = html.replace("__HISTORY__", hist_html)

        b = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type","text/html; charset=utf-8")
        self.send_header("Content-Length",str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a): pass

def main():
    port = 9091
    HTTPServer(("127.0.0.1", port), DashHandler).serve_forever()

if __name__ == "__main__":
    main()
