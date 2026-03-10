#!/bin/bash
# Honeypot Intelligence Viewer
# Usage: ./honeypot-intel.sh [command]
#
# Commands:
#   live      - tail the intel log in real-time
#   summary   - show attack summary (IPs, top usernames, top passwords)
#   creds     - show all username:password combos tried
#   ips       - show unique IPs and attempt counts
#   passwords - show most-tried passwords ranked
#   usernames - show most-tried usernames ranked
#   countries - show attacks by country (requires Cloudflare)
#   timeline  - show attacks over time
#   ip <addr> - show all activity from a specific IP
#   banned    - show currently banned IPs
#   raw       - dump raw JSON log

# --- Configuration ---
# Source config.env if it exists (next to this script or in parent dir)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
for cfg in "$SCRIPT_DIR/config.env" "$SCRIPT_DIR/../config.env"; do
    [ -f "$cfg" ] && source "$cfg" && break
done

# Defaults (override via config.env)
: "${TARGET_HOST:=""}"
: "${TARGET_VMID:=""}"
: "${INTEL_FILE:="/var/log/wp-honeypot-intel.jsonl"}"
: "${F2B_JAIL:="wp-honeypot"}"

# Build command prefix based on deployment mode
if [ -n "$TARGET_VMID" ] && [ -n "$TARGET_HOST" ]; then
    # Proxmox LXC mode
    RUN="ssh $TARGET_HOST pct exec $TARGET_VMID --"
elif [ -n "$TARGET_HOST" ]; then
    # Remote SSH mode
    RUN="ssh $TARGET_HOST"
else
    # Local mode
    RUN=""
fi

CMD_INTEL="$RUN cat $INTEL_FILE"
CMD_TAIL="$RUN tail -f $INTEL_FILE"
CMD_F2B="$RUN fail2ban-client status $F2B_JAIL"

case "${1:-summary}" in

  live)
    echo "=== Live Honeypot Feed (Ctrl+C to stop) ==="
    $CMD_TAIL | while read line; do
      echo "$line" | python3 -c "
import sys, json
for line in sys.stdin:
    d = json.loads(line)
    ip = d.get('ip','?')
    user = d.get('username','')
    pw = d.get('password','')
    attempt = d.get('attempt', 0)
    country = d.get('country','??')
    delay = d.get('delay_applied', 0)
    ts = d.get('timestamp','')[:19]
    if d.get('type') == 'recon':
        print(f'  [{ts}] RECON {ip} ({country}) -> {d.get(\"uri\",\"\")}')
    else:
        print(f'  [{ts}] #{attempt} {ip} ({country}) tried {user}:{pw} [+{delay}s tarpit]')
" 2>/dev/null
    done
    ;;

  summary)
    echo "=== Honeypot Intelligence Summary ==="
    echo ""
    $CMD_F2B 2>/dev/null
    echo ""
    echo "--- Top 10 Usernames ---"
    $CMD_INTEL 2>/dev/null | python3 -c "
import sys, json
from collections import Counter
users = Counter()
for line in sys.stdin:
    try:
        d = json.loads(line)
        if d.get('username'): users[d['username']] += 1
    except: pass
for u, c in users.most_common(10):
    print(f'  {c:>4}x  {u}')
" 2>/dev/null
    echo ""
    echo "--- Top 10 Passwords ---"
    $CMD_INTEL 2>/dev/null | python3 -c "
import sys, json
from collections import Counter
pws = Counter()
for line in sys.stdin:
    try:
        d = json.loads(line)
        if d.get('password'): pws[d['password']] += 1
    except: pass
for p, c in pws.most_common(10):
    print(f'  {c:>4}x  {p}')
" 2>/dev/null
    echo ""
    echo "--- Unique IPs ---"
    $CMD_INTEL 2>/dev/null | python3 -c "
import sys, json
from collections import Counter
ips = Counter()
for line in sys.stdin:
    try:
        d = json.loads(line)
        country = d.get('country','??')
        ips[f\"{d['ip']} ({country})\"] += 1
    except: pass
for ip, c in ips.most_common(20):
    print(f'  {c:>4} attempts  {ip}')
" 2>/dev/null
    ;;

  creds)
    echo "=== All Credential Pairs ==="
    $CMD_INTEL 2>/dev/null | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        d = json.loads(line)
        if d.get('username') and d.get('password'):
            ip = d.get('ip','?')
            ts = d.get('timestamp','')[:19]
            print(f'  [{ts}] {ip:>15}  {d[\"username\"]}:{d[\"password\"]}')
    except: pass
" 2>/dev/null
    ;;

  passwords)
    echo "=== Password Frequency (all attempts) ==="
    $CMD_INTEL 2>/dev/null | python3 -c "
import sys, json
from collections import Counter
pws = Counter()
for line in sys.stdin:
    try:
        d = json.loads(line)
        if d.get('password'): pws[d['password']] += 1
    except: pass
for p, c in sorted(pws.items(), key=lambda x: -x[1]):
    print(f'  {c:>4}x  {p}')
" 2>/dev/null
    ;;

  usernames)
    echo "=== Username Frequency (all attempts) ==="
    $CMD_INTEL 2>/dev/null | python3 -c "
import sys, json
from collections import Counter
users = Counter()
for line in sys.stdin:
    try:
        d = json.loads(line)
        if d.get('username'): users[d['username']] += 1
    except: pass
for u, c in sorted(users.items(), key=lambda x: -x[1]):
    print(f'  {c:>4}x  {u}')
" 2>/dev/null
    ;;

  countries)
    echo "=== Attacks by Country ==="
    $CMD_INTEL 2>/dev/null | python3 -c "
import sys, json
from collections import Counter
countries = Counter()
for line in sys.stdin:
    try:
        d = json.loads(line)
        c = d.get('country') or 'unknown'
        countries[c] += 1
    except: pass
for c, n in countries.most_common():
    print(f'  {n:>4} attempts  {c}')
" 2>/dev/null
    ;;

  timeline)
    echo "=== Attack Timeline (by hour) ==="
    $CMD_INTEL 2>/dev/null | python3 -c "
import sys, json
from collections import Counter
hours = Counter()
for line in sys.stdin:
    try:
        d = json.loads(line)
        hour = d.get('timestamp','')[:13]
        if hour: hours[hour] += 1
    except: pass
for h, c in sorted(hours.items()):
    bar = '#' * min(c, 60)
    print(f'  {h}  {bar} ({c})')
" 2>/dev/null
    ;;

  ip)
    if [ -z "$2" ]; then echo "Usage: $0 ip <address>"; exit 1; fi
    echo "=== All activity from $2 ==="
    $CMD_INTEL 2>/dev/null | python3 -c "
import sys, json
target = '$2'
for line in sys.stdin:
    try:
        d = json.loads(line)
        if d.get('ip') == target:
            ts = d.get('timestamp','')[:19]
            if d.get('type') == 'recon':
                print(f'  [{ts}] RECON -> {d.get(\"uri\",\"\")}')
                ua = d.get('headers',{}).get('user_agent','')
                if ua: print(f'           UA: {ua[:80]}')
            else:
                print(f'  [{ts}] #{d[\"attempt\"]} tried {d.get(\"username\",\"\")}:{d.get(\"password\",\"\")} [+{d.get(\"delay_applied\",0)}s]')
    except: pass
" 2>/dev/null
    ;;

  banned)
    echo "=== Currently Banned IPs ==="
    $CMD_F2B 2>/dev/null
    ;;

  raw)
    $CMD_INTEL 2>/dev/null
    ;;

  *)
    echo "Usage: $0 {live|summary|creds|ips|passwords|usernames|countries|timeline|ip <addr>|banned|raw}"
    ;;
esac
