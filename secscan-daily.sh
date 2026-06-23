#!/bin/bash
# secscan-daily.sh — run daily scan, alert via Telegram if critical/high findings
set -euo pipefail

BOT_TOKEN="8947248891:AAGtA2msm7vPN70pGeU7dieAsHVnKJpoRwo"
CHAT_ID="8246653533"
REPORT_DIR="/var/lib/secscan/reports"
DATE=$(date +%Y%m%d)
REPORT_FILE="${REPORT_DIR}/scan-${DATE}.json"

mkdir -p "$REPORT_DIR"

# Run scan, save JSON report
/usr/local/bin/secscan --format json --output "$REPORT_FILE" 2>/dev/null || true

# Parse findings
CRIT=$(python3 -c "import json; r=json.load(open('$REPORT_FILE')); print(r.get('criticals',0))" 2>/dev/null || echo "0")
HIGH=$(python3 -c "import json; r=json.load(open('$REPORT_FILE')); print(r.get('highs',0))" 2>/dev/null || echo "0")
MED=$(python3 -c "import json; r=json.load(open('$REPORT_FILE')); print(r.get('mediums',0))" 2>/dev/null || echo "0")
LOW=$(python3 -c "import json; r=json.load(open('$REPORT_FILE')); print(r.get('lows',0))" 2>/dev/null || echo "0")
TOTAL=$(python3 -c "import json; r=json.load(open('$REPORT_FILE')); print(r.get('total_findings',0))" 2>/dev/null || echo "0")

# Build summary message
HOSTNAME=$(hostname)
FINDINGS=$(python3 -c "
import json
r = json.load(open('$REPORT_FILE'))
lines = []
for f in r.get('findings', []):
    if f['severity'] in ('Critical','High'):
        lines.append(f'🔴 [{f[\"category\"]}] {f[\"title\"]}')
    elif f['severity'] == 'Medium':
        lines.append(f'🟡 [{f[\"category\"]}] {f[\"title\"]}')
lines = lines[:8]  # top 8
print('\n'.join(lines))
" 2>/dev/null || echo "(no details)")

MSG="🛡️ <b>secscan — $HOSTNAME</b>
📅 $(date '+%Y-%m-%d %H:%M:%S')
📊 Total: $TOTAL | 🔴 $CRIT | 🟡 $HIGH | 🟢 $MED | ⚪ $LOW

<b>Top issues:</b>
$FINDINGS

➡️ <code>curl http://127.0.0.1:9090/report/latest</code>"

# Send to Telegram
if [ "$CRIT" -gt 0 ] || [ "$HIGH" -gt 0 ]; then
    curl -s -X POST "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" \
        -d "chat_id=${CHAT_ID}" \
        -d "text=${MSG}" \
        -d "parse_mode=HTML" \
        -d "disable_web_page_preview=true" > /dev/null
    echo "Alert sent (Critical: $CRIT, High: $HIGH)"
else
    echo "No critical/high findings. Skipping alert."
fi

# Rotate old reports (keep 30 days)
find "$REPORT_DIR" -name "scan-*.json" -mtime +30 -delete 2>/dev/null || true
