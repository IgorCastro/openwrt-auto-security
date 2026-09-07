#!/bin/sh
# Monitoring Script - Provides security analytics and reports
# Part of OpenWRT Auto-Security System
# Version: 2.0 - Enhanced parsing, live timeout, correlation

INSTALL_DIR="/opt/auto-security"
CONFIG_FILE="$INSTALL_DIR/auto-security.conf"

# Load configuration
[ -f "$CONFIG_FILE" ] && . "$CONFIG_FILE"

# Default values
LOG_RETENTION=${LOG_RETENTION:-30}
LIVE_TIMEOUT=${LIVE_TIMEOUT:-300}  # 5 minutes default

# Parse logread once and cache
get_cached_logs() {
    local pattern="$1"
    logread | grep "$pattern" | grep "$(date +'%b %d')"
}

# Get all blocked WAN logs for today
get_blocked_logs() {
    get_cached_logs "Log-Blocked-WAN-Access"
}

# Extract IP from log line (handles IPv4 and IPv6)
extract_ip() {
    local line="$1"
    # Try IPv4 first
    echo "$line" | sed -n 's/.*SRC=\([0-9.]*\).*/\1/p' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
    # If no IPv4, try IPv6
    [ -z "$IP" ] && echo "$line" | sed -n 's/.*SRC=\([0-9a-fA-F:]*\).*/\1/p' | grep ':'
}

# Extract destination port
extract_port() {
    echo "$1" | sed -n 's/.*DPT=\([0-9]*\).*/\1/p'
}

# Extract protocol
extract_proto() {
    echo "$1" | sed -n 's/.*PROTO=\([A-Z]*\).*/\1/p'
}

# Get service name from port
get_service_name() {
    case $1 in
        22) echo "SSH" ;;
        23) echo "Telnet" ;;
        25) echo "SMTP" ;;
        53) echo "DNS" ;;
        80) echo "HTTP" ;;
        110) echo "POP3" ;;
        143) echo "IMAP" ;;
        443) echo "HTTPS" ;;
        465) echo "SMTPS" ;;
        587) echo "Submission" ;;
        993) echo "IMAPS" ;;
        995) echo "POP3S" ;;
        3306) echo "MySQL" ;;
        3389) echo "RDP" ;;
        5432) echo "PostgreSQL" ;;
        5900) echo "VNC" ;;
        8080) echo "HTTP-Alt" ;;
        8443) echo "HTTPS-Alt" ;;
        *) echo "Unknown" ;;
    esac
}

# Generate correlation report with mwan3, AdGuard, netdata
generate_correlation_report() {
    echo "🔗 SERVICE CORRELATION REPORT"
    echo "=============================================="
    
    # mwan3 status
    echo "📡 MWAN3 Status:"
    if command -v mwan3 >/dev/null 2>&1; then
        mwan3 status 2>/dev/null | head -20 | sed 's/^/   /'
    else
        echo "   mwan3 not installed"
    fi
    echo ""
    
    # AdGuard stats
    echo "🛡️  AdGuard Home:"
    if [ -f /etc/AdGuardHome.yaml ]; then
        # Check if AdGuard is running
        if pgrep -f "AdGuardHome" >/dev/null; then
            echo "   Status: Running"
            # Try to get stats from API
            curl -s -u "admin:$(cat /root/adguard-admin.txt 2>/dev/null | cut -d' ' -f2)" \
                http://127.0.0.1:3000/control/stats 2>/dev/null | \
            grep -E '"dns_queries"|"blocked"' | head -5 | sed 's/^/   /'
        else
            echo "   Status: Stopped"
        fi
    else
        echo "   Not configured"
    fi
    echo ""
    
    # netdata status
    echo "📊 Netdata:"
    if pgrep -f "netdata" >/dev/null; then
        echo "   Status: Running on port 19999"
        # Get basic metrics
        curl -s http://127.0.0.1:19999/api/v1/info 2>/dev/null | \
        grep -E '"version"|"uptime"' | head -3 | sed 's/^/   /'
    else
        echo "   Status: Stopped"
    fi
    echo ""
    
    # Correlation: Attacks vs mwan3 interface
    echo "🔍 Attack Source Interface Analysis:"
    get_blocked_logs | \
    sed -n 's/.*IN=\([^ ]*\).*/\1/p' | sort | uniq -c | sort -nr | \
    while read count iface; do
        echo "   $iface: $count attacks"
    done
    echo ""
}

generate_report() {
    local LOGS=$(get_blocked_logs)
    local TOTAL_ATTACKS=$(echo "$LOGS" | wc -l)
    local UNIQUE_IPS=$(echo "$LOGS" | sed -n 's/.*SRC=\([0-9.]*\).*/\1/p' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u | wc -l)
    local UNIQUE_IPV6=$(echo "$LOGS" | sed -n 's/.*SRC=\([0-9a-fA-F:]*\).*/\1/p' | grep ':' | sort -u | wc -l)
    
    echo "=============================================="
    echo "  OpenWRT Auto-Security Status Report v2.0"
    echo "  Generated: $(date)"
    echo "=============================================="
    echo ""
    
    echo "🛡️  PROTECTION STATUS:"
    echo "   Active banned IPs: $(nft list ruleset 2>/dev/null | grep -c 'auto-banned')"
    echo "   Total attacks today: $TOTAL_ATTACKS"
    echo "   Unique IPv4 attackers: $UNIQUE_IPS"
    echo "   Unique IPv6 attackers: $UNIQUE_IPV6"
    echo "   Scan interval: ${SCAN_INTERVAL:-15} minutes"
    echo "   Attack threshold: ${ATTACK_THRESHOLD:-5}"
    echo ""
    
    echo "🎯 TOP THREAT SOURCES (Last 24 hours):"
    echo "$LOGS" | \
    sed -n 's/.*SRC=\([0-9.]*\).*/\1/p' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | \
    sort | uniq -c | sort -nr | head -10 | \
    while read count ip; do
        local country=$(get_country "$ip" 2>/dev/null || echo "Unknown")
        echo "   $ip: $count attacks ($country)"
    done
    echo ""
    
    # IPv6 threats
    local IPV6_COUNT=$(echo "$LOGS" | sed -n 's/.*SRC=\([0-9a-fA-F:]*\).*/\1/p' | grep ':' | sort -u | wc -l)
    if [ "$IPV6_COUNT" -gt 0 ]; then
        echo "🌐 TOP IPv6 THREATS:"
        echo "$LOGS" | \
        sed -n 's/.*SRC=\([0-9a-fA-F:]*\).*/\1/p' | grep ':' | \
        sort | uniq -c | sort -nr | head -5 | \
        while read count ip; do
            echo "   $ip: $count attacks"
        done
        echo ""
    fi
    
    echo "🔍 TARGET PORT ANALYSIS:"
    echo "$LOGS" | \
    grep -o "DPT=[0-9]*" | sed 's/DPT=//' | sort | uniq -c | sort -nr | head -10 | \
    while read count port; do
        local service=$(get_service_name "$port")
        echo "   Port $port ($service): $count attempts"
    done
    echo ""
    
    echo "🌐 PROTOCOL BREAKDOWN:"
    echo "$LOGS" | \
    grep -o "PROTO=[A-Z]*" | sed 's/PROTO=//' | sort | uniq -c | sort -nr | \
    while read count proto; do
        echo "   $proto: $count"
    done
    echo ""
    
    echo "📡 INTERFACE BREAKDOWN:"
    echo "$LOGS" | \
    sed -n 's/.*IN=\([^ ]*\).*/\1/p' | sort | uniq -c | sort -nr | \
    while read count iface; do
        echo "   $iface: $count attacks"
    done
    echo ""
    
    echo "📊 RECENT ACTIVITY (Last 10):"
    echo "$LOGS" | tail -10 | while read line; do
        local timestamp=$(echo "$line" | cut -d' ' -f1-4)
        local ip=$(extract_ip "$line")
        local port=$(extract_port "$line")
        local proto=$(extract_proto "$line")
        local service=$(get_service_name "$port")
        printf "   %s | %-15s | %-5s | %s (%s)\n" "$timestamp" "$ip" "$proto" "$port" "$service"
    done
    echo ""
    
    echo "🚫 CURRENTLY BANNED IPs:"
    nft list ruleset 2>/dev/null | grep "auto-banned" | sed 's/.*\(ip\|ip6\) saddr \([^ ]*\) .*/\2/' | \
    while read ip; do
        local count=$(grep "$ip" "$INSTALL_DIR/logs/banlist.txt" 2>/dev/null | tail -1 | cut -d' ' -f4)
        local fam=$(grep "$ip" "$INSTALL_DIR/logs/banlist.txt" 2>/dev/null | tail -1 | cut -d' ' -f5)
        echo "   $ip (${fam:-ipv4}) - ${count:-unknown} attacks"
    done
    echo ""
    
    # CIDR bans
    local CIDR_BANS=$(nft list ruleset 2>/dev/null | grep "auto-banned-cidr" | wc -l)
    if [ "$CIDR_BANS" -gt 0 ]; then
        echo "🌐 BANNED CIDR RANGES:"
        nft list ruleset 2>/dev/null | grep "auto-banned-cidr" | sed 's/.*ip saddr \([^ ]*\) .*/\1/' | \
        while read cidr; do
            echo "   $cidr"
        done
        echo ""
    fi
    
    # Whitelist status
    if [ -f "/opt/auto-security/config/whitelist.txt" ]; then
        local WL_COUNT=$(wc -l < /opt/auto-security/config/whitelist.txt)
        echo "✅ WHITELIST: $WL_COUNT entries"
    fi
    echo ""
    
    echo "=============================================="
}

# Helper: get country from IP (requires geoip or external API)
get_country() {
    local ip=$1
    # Try local geoip if available
    if command -v geoiplookup >/dev/null 2>&1; then
        geoiplookup "$ip" 2>/dev/null | cut -d':' -f2 | cut -d',' -f1 | xargs
    else
        echo "Unknown"
    fi
}

live_monitor() {
    echo "🔴 LIVE ATTACK MONITORING (Timeout: ${LIVE_TIMEOUT}s, Press Ctrl+C to stop)"
    echo "Timestamp                 | Proto | Source IP              | Port | Service"
    echo "--------------------------------------------------------------------------------"
    
    # Use timeout for safety
    timeout "$LIVE_TIMEOUT" logread -f | grep --line-buffered "Log-Blocked-WAN-Access" | while read line; do
        local timestamp=$(echo "$line" | cut -d' ' -f1-4)
        local ip=$(extract_ip "$line")
        local port=$(extract_port "$line")
        local proto=$(extract_proto "$line")
        local service=$(get_service_name "$port")
        printf "%-25s | %-5s | %-22s | %-5s | %s\n" "$timestamp" "$proto" "$ip" "$port" "$service"
    done
    
    echo ""
    echo "Live monitoring stopped (timeout or Ctrl+C)"
}

list_banned() {
    echo "🚫 CURRENTLY BANNED IPs:"
    echo "IP Address              | Family | Attacks | Date Banned"
    echo "------------------------------------------------------------"
    nft list ruleset 2>/dev/null | grep "auto-banned" | \
    sed 's/.*\(ip\|ip6\) saddr \([^ ]*\) counter.*comment "auto-banned-\([^"]*\)"/\1 \2 \3/' | \
    while read fam ip comment; do
        local count=$(grep "$ip" "$INSTALL_DIR/logs/banlist.txt" 2>/dev/null | tail -1 | cut -d' ' -f4)
        local date=$(grep "$ip" "$INSTALL_DIR/logs/banlist.txt" 2>/dev/null | tail -1 | cut -d' ' -f1,2)
        printf "%-22s | %-6s | %-7s | %s\n" "$ip" "$fam" "${count:-?}" "${date:-?}"
    done
    
    # CIDR bans
    nft list ruleset 2>/dev/null | grep "auto-banned-cidr" | \
    sed 's/.*ip saddr \([^ ]*\) counter.*comment "auto-banned-cidr-\([^"]*\)"/\1 \2/' | \
    while read cidr comment; do
        printf "%-22s | CIDR   | N/A     | -\n" "$cidr"
    done
}

show_whitelist() {
    echo "✅ WHITELIST ENTRIES:"
    if [ -f "/opt/auto-security/config/whitelist.txt" ]; then
        cat /opt/auto-security/config/whitelist.txt | while read line; do
            echo "   $line"
        done
    else
        echo "   (empty)"
    fi
}

add_whitelist() {
    local entry=$1
    [ -z "$entry" ] && { echo "Usage: $0 whitelist-add <IP|CIDR>"; exit 1; }
    
    mkdir -p /opt/auto-security/config
    touch /opt/auto-security/config/whitelist.txt
    
    if grep -q "^$entry$" /opt/auto-security/config/whitelist.txt; then
        echo "Already in whitelist: $entry"
    else
        echo "$entry" >> /opt/auto-security/config/whitelist.txt
        echo "Added to whitelist: $entry"
    fi
}

remove_whitelist() {
    local entry=$1
    [ -z "$entry" ] && { echo "Usage: $0 whitelist-remove <IP|CIDR>"; exit 1; }
    
    if [ -f "/opt/auto-security/config/whitelist.txt" ]; then
        grep -v "^$entry$" /opt/auto-security/config/whitelist.txt > /tmp/whitelist.tmp
        mv /tmp/whitelist.tmp /opt/auto-security/config/whitelist.txt
        echo "Removed from whitelist: $entry"
    fi
}

unban_ip() {
    local ip=$1
    [ -z "$ip" ] && { echo "Usage: $0 unban <IP>"; exit 1; }
    
    echo "🔓 Unbanning $ip..."
    nft delete rule inet fw4 input_wan ip saddr $ip counter drop comment "auto-banned-$ip" 2>/dev/null
    nft delete rule inet fw4 input_wan ip6 saddr $ip counter drop comment "auto-banned-$ip" 2>/dev/null
    echo "Done (if IP was banned)"
}

reset_bans() {
    echo "🔄 Removing all auto-bans..."
    nft list ruleset | grep "auto-banned" | \
    sed 's/.*\(ip\|ip6\) saddr \([^ ]*\) counter.*comment "auto-banned-\([^"]*\)"/\1 \2 \3/' | \
    while read fam ip comment; do
        nft delete rule inet fw4 input_wan ${fam} saddr $ip counter drop comment "auto-banned-$comment" 2>/dev/null
    done
    echo "All bans removed"
}

save_bans() {
    echo "💾 Saving current bans to persistent storage..."
    mkdir -p /opt/auto-security/backup
    nft list ruleset | grep "auto-banned" > /opt/auto-security/backup/nftables_bans.nft
    cp /opt/auto-security/logs/banlist.txt /opt/auto-security/backup/ 2>/dev/null
    cp /opt/auto-security/logs/cidr_banlist.txt /opt/auto-security/backup/ 2>/dev/null
    echo "Bans saved to /opt/auto-security/backup/"
}

restore_bans() {
    echo "📥 Restoring bans from persistent storage..."
    if [ -f /opt/auto-security/backup/nftables_bans.nft ]; then
        nft -f /opt/auto-security/backup/nftables_bans.nft
        echo "Bans restored from backup"
    else
        echo "No backup found"
    fi
}

case "$1" in
    "report")
        generate_report
        ;;
    "correlation")
        generate_correlation_report
        ;;
    "live")
        live_monitor
        ;;
    "banned")
        list_banned
        ;;
    "whitelist")
        show_whitelist
        ;;
    "whitelist-add")
        add_whitelist "$2"
        ;;
    "whitelist-remove")
        remove_whitelist "$2"
        ;;
    "unban")
        unban_ip "$2"
        ;;
    "reset")
        reset_bans
        ;;
    "save")
        save_bans
        ;;
    "restore")
        restore_bans
        ;;
    *)
        echo "OpenWRT Auto-Security Monitor v2.0"
        echo ""
        echo "Usage: $0 {command}"
        echo ""
        echo "Reporting:"
        echo "  report       - Generate full security status report"
        echo "  correlation  - Show correlation with mwan3/AdGuard/netdata"
        echo "  live         - Monitor attacks in real-time (5 min timeout)"
        echo "  banned       - List currently banned IPs with details"
        echo ""
        echo "Whitelist Management:"
        echo "  whitelist          - Show whitelist entries"
        echo "  whitelist-add IP   - Add IP/CIDR to whitelist"
        echo "  whitelist-remove IP- Remove IP/CIDR from whitelist"
        echo ""
        echo "Ban Management:"
        echo "  unban IP    - Remove specific IP from ban list"
        echo "  reset       - Remove all bans"
        echo "  save        - Save bans to persistent storage"
        echo "  restore     - Restore bans from backup"
        echo ""
        echo "Examples:"
        echo "  $0 report"
        echo "  $0 live"
        echo "  $0 whitelist-add 192.168.1.100"
        echo "  $0 whitelist-add 10.0.0.0/8"
        echo "  $0 unban 1.2.3.4"
        ;;
esac