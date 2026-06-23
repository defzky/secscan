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

def get_report_by_id(id):
    d = fetch_json(f"{API_URL}/report/{id}")
    if d and d.get("success"): return d["data"]
    return None

def get_reports():
    if not REPORT_DIR.exists(): return []
    out = []
    for r in sorted(REPORT_DIR.glob("scan-*.json"), reverse=True)[:30]:
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

def get_all_health():
    """Health check for all secscan services."""
    results = {}
    # API server
    api = fetch_json(f"{API_URL}/health")
    results["api"] = api if api else {"status": "error", "service": "secscan-api"}
    # Dashboard itself
    results["dash"] = {"status": "ok", "service": "secscan-dash"}
    # Service status via systemd
    import subprocess
    for svc in ["secscan", "secscan-dash", "secscan-daily"]:
        try:
            r = subprocess.run(["systemctl", "is-active", f"{svc}.service"],
                               capture_output=True, text=True, timeout=3)
            results[svc] = {"status": r.stdout.strip()}
        except:
            results[svc] = {"status": "unknown"}
    # Memory
    try:
        for svc in ["secscan", "secscan-dash"]:
            r = subprocess.run(
                ["sh", "-c", f"ps -o rss= -p $(systemctl show {svc}.service -p MainPID --value 2>/dev/null) 2>/dev/null"],
                capture_output=True, text=True, timeout=3)
            mem = r.stdout.strip()
            results[f"{svc}_mem_kb"] = mem if mem else "N/A"
    except:
        pass
    return results

TEMPLATE = (Path(__file__).parent / "dash.html").read_text()

class DashHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        p = self.path.split("?")[0]

        if p == "/" or p == "":
            self.send_dash()
        elif p == "/health":
            if "json" in self.headers.get("Accept", ""):
                self.send_json(get_all_health())
            else:
                self.send_health_page()
        elif p == "/reports":
            if "json" in self.headers.get("Accept", ""):
                self.send_json(get_reports())
            else:
                self.send_reports_page()
        elif p.startswith("/report/"):
            rid = p.replace("/report/", "").strip("/")
            if rid:
                self.send_report_page(rid)
            else:
                self.send_report_page("latest")
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path == "/scan" or self.path == "/api/scan":
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

    def send_html(self, body):
        b = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type","text/html; charset=utf-8")
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
            cw = (crit/max(total,1))*100
            hw = (high/max(total,1))*100
            mw = (med/max(total,1))*100
            lw = (low/max(total,1))*100
            iw = (info/max(total,1))*100
            rid = s.get("report_id", "")

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
                findings_html += f'''
                <details class="finding-details">
                  <summary><span class="sev-tag sev-{sev}">{f["severity"]}</span> <span class="cat-tag">[{cat}]</span> {f["title"]}</summary>
                  <p class="desc">{f["description"]}</p>
                  <p class="fix">&#8594; {f.get("remediation","")}</p>
                </details>
                '''
            findings_html += f'</div><p style="margin-top:8px"><a class="btn" href="/report/{rid}">📄 Full Report</a></p>'
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

        html = TEMPLATE
        html = html.replace("__TITLE__", "secscan — Dashboard")
        html = html.replace("__CONTENT__",
            f'<div class="actions"><button class="btn btn-primary" onclick="runScan()" id="scanBtn">🔄 Run Scan</button></div>'
            f'{summary_html}{findings_html}{hist_html}')
        html = html.replace("__SCRIPT__", """
<script>
function showToast(msg, isError) {
  var t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast' + (isError ? ' error' : '') + ' show';
  setTimeout(function() { t.classList.remove('show'); }, 4000);
}
async function runScan() {
  var btn = document.getElementById('scanBtn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Scanning...';
  try {
    var r = await fetch(BASE + '/api/scan', { method: 'POST' });
    var d = await r.json();
    if (d.success) {
      showToast('Scan done: ' + d.data.summary.total + ' findings');
      setTimeout(function() { location.reload(); }, 1500);
    } else {
      showToast('Scan failed', true);
    }
  } catch(e) {
    showToast('Error: ' + e.message, true);
  }
  btn.disabled = false;
  btn.innerHTML = '🔄 Run Scan';
}
</script>""")
        self.send_html(html)

    def send_health_page(self):
        h = get_all_health()
        cards = ""
        status_color = {"active": "var(--green)", "inactive": "var(--red)", "unknown": "var(--text-muted)"}

        for key in ["api", "dash", "secscan", "secscan-dash", "secscan-daily"]:
            if key not in h: continue
            st = h[key].get("status", "unknown")
            color = status_color.get(st, "var(--text-muted)")
            svc_name = key.replace("_", " ").title()
            mem = ""
            mem_k = h.get(f"{key}_mem_kb")
            if mem_k and mem_k != "N/A":
                mem = f"<span class='stat-sub'>{int(mem_k)//1024}MB RSS</span>"
            cards += f"""
            <div class="health-card">
              <div class="health-indicator" style="background:{color}"></div>
              <div class="health-info">
                <div class="health-name">{svc_name}</div>
                <div class="health-status" style="color:{color}">{st.upper()}</div>
                {mem}
              </div>
            </div>"""

        # Host info
        uptime_s = 0
        try:
            with open("/proc/uptime") as f:
                uptime_s = float(f.read().split()[0])
        except: pass
        uptime_str = f"{int(uptime_s//86400)}d {int((uptime_s%86400)//3600)}h" if uptime_s else "N/A"
        try:
            mem_total = round(int(os.popen("grep MemTotal /proc/meminfo").read().split()[1]) / 1024)
            mem_free = round(int(os.popen("grep MemAvailable /proc/meminfo").read().split()[1]) / 1024)
            mem_pct = round((1 - mem_free/mem_total)*100)
        except:
            mem_total, mem_free, mem_pct = "?", "?", "?"

        host_info = f"""
        <div class="health-card"><div class="health-info">
          <div class="health-name">Host</div>
          <div class="health-status">{HOSTNAME}</div>
          <span class="stat-sub">{mem_total}MB total · {mem_pct}% used · up {uptime_str}</span>
        </div></div>"""

        content = f"""
        <div class="section-title">❤️ System Health</div>
        <div class="health-grid">
          {host_info}
          {cards}
        </div>
        <div class="section-title" style="margin-top:24px">📌 Quick Checks</div>
        <table class="report-table">
          <thead><tr><th>Check</th><th>Result</th></tr></thead>
          <tbody>
            <tr><td>Nginx</td><td>{"✅ " if fetch_json("http://127.0.0.1:9090/health") else "❌"} API reachable</td></tr>
            <tr><td>Python</td><td>✅ {os.popen("python3 --version 2>&1").read().strip()}</td></tr>
            <tr><td>Disk</td><td>✅ {os.popen("df -h / | tail -1 | awk '{print $3\"/\"$2\" (\"$5\")\"}'").read().strip()}</td></tr>
          </tbody>
        </table>
        """

        html = TEMPLATE
        html = html.replace("__TITLE__", "secscan — Health")
        html = html.replace("__CONTENT__", content)
        html = html.replace("__SCRIPT__", "")

        # Auto-refresh every 30s
        html = html.replace("</head>", '<meta http-equiv="refresh" content="30"></head>')
        self.send_html(html)

    def send_reports_page(self):
        reports = get_reports()
        rows = ""
        for r in reports:
            dots = ""
            if r.get("crit",0)>0: dots+='<span class="dot-red"></span> '
            if r.get("high",0)>0: dots+='<span class="dot-yellow"></span> '
            if r.get("med",0)>0: dots+='<span class="dot-yellow"></span> '
            sev_cls = "row-critical" if r.get("crit",0)>0 else ("row-high" if r.get("high",0)>0 else "")
            rows += f"<tr class='{sev_cls}'><td>{r['date']}</td><td>{r['file']}</td><td>{dots}</td><td>{r.get('total',0)}</td><td>{r.get('crit',0)}/{r.get('high',0)}/{r.get('med',0)}</td></tr>"

        empty_row = '<tr><td colspan="5" class="empty">No reports yet</td></tr>' if not rows else ""
        content = f"""
        <div class="section-title">📋 All Scan Reports</div>
        <p class="count-badge">Total: {len(reports)} reports</p>
        <table class="report-table">
          <thead><tr><th>Date</th><th>File</th><th>Sev</th><th>Total</th><th>C/H/M</th></tr></thead>
          <tbody>{rows or empty_row}</tbody>
        </table>
        """
        html = TEMPLATE
        html = html.replace("__TITLE__", "secscan — Reports")
        html = html.replace("__CONTENT__", content)
        html = html.replace("__SCRIPT__", "")
        self.send_html(html)

    def send_report_page(self, rid):
        if rid == "latest":
            report = get_latest()
        else:
            report = get_report_by_id(rid)

        if not report:
            self.send_html(f"""
            <html><body style="font-family:sans-serif;background:#0d1117;color:#c9d1d9;padding:40px;text-align:center">
              <h2>Report not found</h2>
              <p>{rid}</p>
              <a href="/">← Back to Dashboard</a>
            </body></html>""")
            return

        s = report
        total = s["total_findings"]
        crit, high, med, low = s["criticals"], s["highs"], s["mediums"], s["lows"]
        ts = s.get("timestamp","")[:19].replace("T"," ")
        dur = s.get("duration_ms", 0)
        host = s.get("hostname", HOSTNAME)

        cw = (crit/max(total,1))*100
        hw = (high/max(total,1))*100
        mw = (med/max(total,1))*100
        lw = (low/max(total,1))*100
        info = total - crit - high - med - low
        iw = (info/max(total,1))*100

        # Group findings by category
        cats = {}
        for f in s["findings"]:
            cat = f["category"]
            if cat not in cats: cats[cat] = []
            cats[cat].append(f)

        cat_html = ""
        for cat in sorted(cats.keys()):
            items = cats[cat]
            crits = sum(1 for f in items if f["severity"] == "Critical")
            highs = sum(1 for f in items if f["severity"] == "High")
            meds = sum(1 for f in items if f["severity"] == "Medium")
            badge = ""
            if crits: badge += f'<span class="sev-tag sev-critical">{crits} critical</span> '
            if highs: badge += f'<span class="sev-tag sev-high">{highs} high</span> '
            if meds: badge += f'<span class="sev-tag sev-medium">{meds} medium</span> '

            details = ""
            for f in items:
                sev = f["severity"].lower()
                details += f'''
                <details class="finding-details">
                  <summary><span class="sev-tag sev-{sev}">{f["severity"]}</span> {f["title"]}</summary>
                  <p class="desc">{f["description"]}</p>
                  <p class="fix">&#8594; {f.get("remediation","")}</p>
                </details>'''

            cat_html += f"""
            <div class="cat-section">
              <div class="cat-header">
                <span class="cat-icon">{"📦" if cat=="Docker" else "🌐" if cat=="Nginx" else "🔌" if cat=="Port" else "⚙️" if cat=="Service" else "🖥️" if cat=="System" else "🔑" if cat=="SSH" else "📁"} {cat}</span>
                {badge}
              </div>
              {details}
            </div>"""

        content = f"""
        <div class="report-header">
          <div class="report-meta">
            <span class="report-host">{host}</span>
            <span class="report-date">{ts}</span>
            <span class="report-dur">{dur}ms</span>
            <span class="report-id" style="font-size:0.75rem;color:var(--text-muted);">ID: {rid}</span>
          </div>
          <a class="btn" href="/">← Dashboard</a>
        </div>

        <div class="stats-grid">
          <div class="stat-card critical"><div class="number">{crit}</div><div class="label">Critical</div></div>
          <div class="stat-card high"><div class="number">{high}</div><div class="label">High</div></div>
          <div class="stat-card medium"><div class="number">{med}</div><div class="label">Medium</div></div>
          <div class="stat-card low"><div class="number">{low}</div><div class="label">Low</div></div>
          <div class="stat-card info"><div class="number">{total}</div><div class="label">Total</div></div>
        </div>
        <div class="severity-bar">
          <div class="segment" style="width:{cw:.1f}%;background:#f85149;"></div>
          <div class="segment" style="width:{hw:.1f}%;background:#d29922;"></div>
          <div class="segment" style="width:{mw:.1f}%;background:#dbb700;"></div>
          <div class="segment" style="width:{lw:.1f}%;background:#3fb950;"></div>
          <div class="segment" style="width:{iw:.1f}%;background:#58a6ff;"></div>
        </div>

        <div class="section-title">🔍 All Findings by Category</div>
        {cat_html}
        """

        html = TEMPLATE
        html = html.replace("__TITLE__", f"secscan — Report {ts}")
        html = html.replace("__CONTENT__", content)
        html = html.replace("__SCRIPT__", "")
        self.send_html(html)

    def log_message(self, *a): pass

def main():
    port = 9091
    HTTPServer(("127.0.0.1", port), DashHandler).serve_forever()

if __name__ == "__main__":
    main()
