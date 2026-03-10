#!/bin/bash
set -euo pipefail
#
# wp-honeypot installer
#
# Deploys the honeypot tarpit + fail2ban to a WordPress server.
# Supports local, remote SSH, and Proxmox LXC targets.
#
# Usage:
#   ./install.sh                          # interactive, reads config.env
#   ./install.sh --local /var/www/html    # local mode
#   ./install.sh --ssh user@host /var/www/html
#   ./install.sh --pct user@proxmox 550 /var/www/html

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# --- Colors ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[!]${NC} $*"; exit 1; }

# --- Parse args or load config ---
MODE=""
HOST=""
VMID=""
WP_ROOT=""

if [ "${1:-}" = "--local" ]; then
    MODE="local"; WP_ROOT="${2:?'Usage: install.sh --local /path/to/wordpress'}"
elif [ "${1:-}" = "--ssh" ]; then
    MODE="ssh"; HOST="${2:?'Usage: install.sh --ssh user@host /path/to/wordpress'}"; WP_ROOT="${3:?}"
elif [ "${1:-}" = "--pct" ]; then
    MODE="pct"; HOST="${2:?'Usage: install.sh --pct user@proxmox VMID /path/to/wordpress'}"; VMID="${3:?}"; WP_ROOT="${4:?}"
else
    # Load config.env
    CFG="$SCRIPT_DIR/config.env"
    if [ ! -f "$CFG" ]; then
        error "No config.env found. Copy config.env.example to config.env and edit it, or use --local/--ssh/--pct flags."
    fi
    source "$CFG"
    WP_ROOT="${WP_ROOT:-/var/www/html}"
    if [ -n "${TARGET_VMID:-}" ] && [ -n "${TARGET_HOST:-}" ]; then
        MODE="pct"; HOST="$TARGET_HOST"; VMID="$TARGET_VMID"
    elif [ -n "${TARGET_HOST:-}" ]; then
        MODE="ssh"; HOST="$TARGET_HOST"
    else
        MODE="local"
    fi
fi

# --- Build remote exec helper ---
run() {
    case "$MODE" in
        local) eval "$@" ;;
        ssh)   ssh "$HOST" "$@" ;;
        pct)   ssh "$HOST" "pct exec $VMID -- bash -c '$*'" ;;
    esac
}

# --- Read site config for template substitution ---
SITE_NAME="${SITE_NAME:-WordPress}"
SITE_URL="${SITE_URL:-}"
LOG_FILE="${LOG_FILE:-/var/log/wp-honeypot.log}"
INTEL_FILE="${INTEL_FILE:-/var/log/wp-honeypot-intel.jsonl}"
STATE_DIR="${STATE_DIR:-/var/lib/wp-honeypot}"
MAX_DELAY="${MAX_DELAY:-30}"
F2B_MAXRETRY="${F2B_MAXRETRY:-20}"
F2B_FINDTIME="${F2B_FINDTIME:-86400}"
F2B_BANTIME="${F2B_BANTIME:-2592000}"

info "Deploying wp-honeypot to $WP_ROOT ($MODE mode)"
[ -n "$HOST" ] && info "  Host: $HOST"
[ -n "$VMID" ] && info "  VMID: $VMID"
info "  Site: $SITE_NAME ($SITE_URL)"

# --- 1. Generate site-specific config ---
info "Generating wp-trap-config.php..."
CONFIG_PHP=$(cat <<CONFIGEOF
<?php
\$site_name  = '$(echo "$SITE_NAME" | sed "s/'/\\\\'/g")';
\$site_url   = '$(echo "$SITE_URL" | sed "s/'/\\\\'/g")';
\$log_file   = '$LOG_FILE';
\$intel_file  = '$INTEL_FILE';
\$state_dir  = '$STATE_DIR';
\$max_delay  = $MAX_DELAY;
CONFIGEOF
)

# --- 2. Copy files to target ---
info "Copying honeypot files..."

copy_file() {
    local src="$1" dst="$2"
    case "$MODE" in
        local) cp "$src" "$dst" ;;
        ssh)   scp -q "$src" "$HOST:$dst" ;;
        pct)
            local tmp="/tmp/wp-honeypot-$(basename "$src")"
            scp -q "$src" "$HOST:$tmp"
            ssh "$HOST" "pct push $VMID $tmp $dst && rm $tmp"
            ;;
    esac
}

write_file() {
    local content="$1" dst="$2"
    case "$MODE" in
        local) echo "$content" > "$dst" ;;
        ssh)   echo "$content" | ssh "$HOST" "cat > $dst" ;;
        pct)
            local tmp="/tmp/wp-honeypot-write-$$"
            echo "$content" | ssh "$HOST" "cat > $tmp && pct push $VMID $tmp $dst && rm $tmp"
            ;;
    esac
}

# Trap script + config
copy_file "$SCRIPT_DIR/trap/wp-trap.php" "$WP_ROOT/wp-trap.php"
write_file "$CONFIG_PHP" "$WP_ROOT/wp-trap-config.php"

# Set permissions
run "chown www-data:www-data $WP_ROOT/wp-trap.php $WP_ROOT/wp-trap-config.php 2>/dev/null || true"
run "chmod 644 $WP_ROOT/wp-trap.php $WP_ROOT/wp-trap-config.php"

# --- 3. Create log files and state directory ---
info "Creating log files and state directory..."
run "touch $LOG_FILE $INTEL_FILE"
run "chown www-data:www-data $LOG_FILE $INTEL_FILE 2>/dev/null || true"
run "chmod 640 $LOG_FILE $INTEL_FILE"
run "mkdir -p $STATE_DIR"
run "chown www-data:www-data $STATE_DIR 2>/dev/null || true"
run "chmod 700 $STATE_DIR"

# --- 4. Install fail2ban if needed ---
info "Checking fail2ban..."
if run "command -v fail2ban-client >/dev/null 2>&1"; then
    info "  fail2ban already installed"
else
    warn "  Installing fail2ban..."
    run "apt-get update -qq && apt-get install -y -qq fail2ban"
fi

# --- 5. Deploy fail2ban configs ---
info "Deploying fail2ban configs..."
copy_file "$SCRIPT_DIR/fail2ban/filter.d/wp-honeypot.conf" "/etc/fail2ban/filter.d/wp-honeypot.conf"

# Generate jail with configured thresholds
JAIL_CONF=$(cat <<JAILEOF
[wp-honeypot]
enabled  = true
port     = http,https
filter   = wp-honeypot
logpath  = $LOG_FILE
maxretry = $F2B_MAXRETRY
findtime = $F2B_FINDTIME
bantime  = $F2B_BANTIME
action   = iptables-multiport[name=wp-honeypot, port="http,https", protocol=tcp]
JAILEOF
)
write_file "$JAIL_CONF" "/etc/fail2ban/jail.d/wp-honeypot.conf"

# Only deploy jail.local if no existing one
if ! run "test -f /etc/fail2ban/jail.local" 2>/dev/null; then
    copy_file "$SCRIPT_DIR/fail2ban/jail.local" "/etc/fail2ban/jail.local"
fi

# Restart fail2ban
info "Restarting fail2ban..."
run "systemctl restart fail2ban"

# --- 6. Inject rewrite rules into .htaccess ---
info "Checking .htaccess..."
HTACCESS="$WP_ROOT/.htaccess"
if run "test -f $HTACCESS" 2>/dev/null; then
    if run "grep -q 'Honeypot Tarpit' $HTACCESS" 2>/dev/null; then
        info "  Honeypot rewrite rules already present"
    else
        warn "  Injecting honeypot rewrite rules into .htaccess..."
        run "cp $HTACCESS ${HTACCESS}.bak.$(date +%s)"
        REWRITE_BLOCK=$(cat "$SCRIPT_DIR/apache/honeypot-rewrite.conf")
        # Inject before WordPress rewrite block
        case "$MODE" in
            local)
                # Insert before "# BEGIN WordPress" or append
                if grep -q "# BEGIN WordPress" "$HTACCESS"; then
                    sed -i "/# BEGIN WordPress/i\\
$(echo "$REWRITE_BLOCK" | sed 's/$/\\/' | sed '$ s/\\$//')
" "$HTACCESS"
                else
                    echo "$REWRITE_BLOCK" >> "$HTACCESS"
                fi
                ;;
            *)
                # For remote: append to end (before WP block requires more complex sed over SSH)
                ESCAPED=$(echo "$REWRITE_BLOCK" | base64 -w0)
                run "echo '$ESCAPED' | base64 -d >> $HTACCESS"
                ;;
        esac
    fi
else
    warn "  No .htaccess found — creating with honeypot rules"
    copy_file "$SCRIPT_DIR/apache/honeypot-rewrite.conf" "$HTACCESS"
fi

# --- 7. Verify ---
info "Verifying installation..."
CHECKS=0

if run "test -f $WP_ROOT/wp-trap.php" 2>/dev/null; then
    info "  wp-trap.php ......... OK"; ((CHECKS++))
else
    warn "  wp-trap.php ......... MISSING"
fi

if run "test -f $WP_ROOT/wp-trap-config.php" 2>/dev/null; then
    info "  wp-trap-config.php .. OK"; ((CHECKS++))
else
    warn "  wp-trap-config.php .. MISSING"
fi

if run "test -f /etc/fail2ban/filter.d/wp-honeypot.conf" 2>/dev/null; then
    info "  fail2ban filter ..... OK"; ((CHECKS++))
else
    warn "  fail2ban filter ..... MISSING"
fi

if run "fail2ban-client status wp-honeypot >/dev/null 2>&1"; then
    info "  fail2ban jail ....... ACTIVE"; ((CHECKS++))
else
    warn "  fail2ban jail ....... INACTIVE"
fi

if run "grep -q 'Honeypot Tarpit' $HTACCESS 2>/dev/null"; then
    info "  .htaccess rules ..... OK"; ((CHECKS++))
else
    warn "  .htaccess rules ..... MISSING"
fi

echo ""
if [ "$CHECKS" -ge 4 ]; then
    info "Installation complete ($CHECKS/5 checks passed)"
    echo ""
    echo "  Fake login:  ${SITE_URL}/wp-login.php"
    echo "  Intel log:   $INTEL_FILE"
    echo "  Viewer:      ./tools/honeypot-intel.sh summary"
    echo ""
else
    warn "Installation incomplete ($CHECKS/5 checks passed) — review warnings above"
fi
